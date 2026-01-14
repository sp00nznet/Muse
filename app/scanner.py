import io
import json
from datetime import datetime
import paramiko
import winrm
from app import db
from app.models import Host, ScanResult


class RemoteScanner:
    """Scanner for remote host metrics via SSH or WinRM."""

    def __init__(self, host: Host, password: str = None):
        self.host = host
        self.password = password or host.password_encrypted
        self.result = ScanResult(host_id=host.id)

    def scan(self) -> ScanResult:
        """Execute scan based on OS type."""
        try:
            if self.host.os_type == 'windows':
                self._scan_windows()
            else:
                self._scan_linux()
            self.result.success = True
            self.host.status = 'online'
        except Exception as e:
            self.result.success = False
            self.result.error_message = str(e)
            self.host.status = 'error'

        self.host.last_scan = datetime.utcnow()
        db.session.add(self.result)
        db.session.commit()
        return self.result

    def _scan_linux(self):
        """Scan Linux host via SSH."""
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        connect_kwargs = {
            'hostname': self.host.ip_address or self.host.hostname,
            'port': self.host.ssh_port,
            'username': self.host.username,
            'timeout': 30
        }

        if self.host.ssh_key:
            key_file = io.StringIO(self.host.ssh_key)
            private_key = paramiko.RSAKey.from_private_key(key_file)
            connect_kwargs['pkey'] = private_key
        elif self.password:
            connect_kwargs['password'] = self.password

        try:
            ssh.connect(**connect_kwargs)

            # Hostname
            self.result.hostname_reported = self._ssh_exec(ssh, 'hostname').strip()

            # OS Info
            self.result.os_info = self._ssh_exec(ssh, 'cat /etc/os-release 2>/dev/null || uname -a')

            # Uptime
            self.result.uptime = self._ssh_exec(ssh, 'uptime -p 2>/dev/null || uptime').strip()

            # CPU Usage
            cpu_output = self._ssh_exec(ssh, "top -bn1 | grep 'Cpu(s)' | awk '{print $2}'")
            try:
                self.result.cpu_usage = float(cpu_output.strip().replace('%', '').replace(',', '.'))
            except (ValueError, AttributeError):
                self.result.cpu_usage = None

            # Memory
            mem_output = self._ssh_exec(ssh, "free -b | grep Mem")
            if mem_output:
                parts = mem_output.split()
                if len(parts) >= 3:
                    self.result.memory_total = int(parts[1])
                    self.result.memory_used = int(parts[2])
                    if self.result.memory_total > 0:
                        self.result.memory_percent = (self.result.memory_used / self.result.memory_total) * 100

            # Disk
            self.result.disk_info = self._ssh_exec(ssh, 'df -h')

            # Logged in users
            self.result.logged_users = self._ssh_exec(ssh, 'who')

            # Processes
            processes = self._ssh_exec(ssh, 'ps aux --no-headers | head -50')
            self.result.running_processes = processes
            process_count = self._ssh_exec(ssh, 'ps aux --no-headers | wc -l')
            try:
                self.result.process_count = int(process_count.strip())
            except (ValueError, AttributeError):
                pass

            # Recent logs
            self.result.recent_logs = self._ssh_exec(
                ssh,
                'journalctl -n 50 --no-pager 2>/dev/null || tail -50 /var/log/syslog 2>/dev/null || tail -50 /var/log/messages 2>/dev/null || echo "No logs available"'
            )

            # Network
            self.result.network_info = self._ssh_exec(ssh, 'ip addr 2>/dev/null || ifconfig')

        finally:
            ssh.close()

    def _ssh_exec(self, ssh, command: str) -> str:
        """Execute SSH command and return output."""
        try:
            stdin, stdout, stderr = ssh.exec_command(command, timeout=30)
            return stdout.read().decode('utf-8', errors='ignore')
        except Exception as e:
            return f"Error: {str(e)}"

    def _scan_windows(self):
        """Scan Windows host via WinRM."""
        session = winrm.Session(
            f'http://{self.host.ip_address or self.host.hostname}:{self.host.winrm_port}/wsman',
            auth=(self.host.username, self.password),
            transport='ntlm'
        )

        # Hostname
        result = session.run_ps('hostname')
        self.result.hostname_reported = result.std_out.decode('utf-8').strip()

        # OS Info
        result = session.run_ps('Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber | ConvertTo-Json')
        self.result.os_info = result.std_out.decode('utf-8')

        # Uptime
        result = session.run_ps('(Get-Date) - (Get-CimInstance Win32_OperatingSystem).LastBootUpTime | Select-Object Days, Hours, Minutes | ConvertTo-Json')
        self.result.uptime = result.std_out.decode('utf-8')

        # CPU Usage
        result = session.run_ps('Get-CimInstance Win32_Processor | Select-Object -ExpandProperty LoadPercentage')
        try:
            self.result.cpu_usage = float(result.std_out.decode('utf-8').strip())
        except (ValueError, AttributeError):
            pass

        # Memory
        result = session.run_ps('Get-CimInstance Win32_OperatingSystem | Select-Object TotalVisibleMemorySize, FreePhysicalMemory | ConvertTo-Json')
        try:
            mem_data = json.loads(result.std_out.decode('utf-8'))
            self.result.memory_total = mem_data['TotalVisibleMemorySize'] * 1024  # KB to bytes
            free_mem = mem_data['FreePhysicalMemory'] * 1024
            self.result.memory_used = self.result.memory_total - free_mem
            self.result.memory_percent = (self.result.memory_used / self.result.memory_total) * 100
        except (json.JSONDecodeError, KeyError, TypeError):
            pass

        # Disk
        result = session.run_ps('Get-PSDrive -PSProvider FileSystem | Select-Object Name, Used, Free | ConvertTo-Json')
        self.result.disk_info = result.std_out.decode('utf-8')

        # Logged in users
        result = session.run_ps('query user 2>$null')
        self.result.logged_users = result.std_out.decode('utf-8')

        # Processes
        result = session.run_ps('Get-Process | Select-Object -First 50 Name, Id, CPU, WorkingSet | ConvertTo-Json')
        self.result.running_processes = result.std_out.decode('utf-8')

        result = session.run_ps('(Get-Process).Count')
        try:
            self.result.process_count = int(result.std_out.decode('utf-8').strip())
        except (ValueError, AttributeError):
            pass

        # Recent logs
        result = session.run_ps('Get-EventLog -LogName System -Newest 50 | Select-Object TimeGenerated, EntryType, Source, Message | ConvertTo-Json')
        self.result.recent_logs = result.std_out.decode('utf-8')

        # Network
        result = session.run_ps('Get-NetIPAddress | Select-Object InterfaceAlias, IPAddress, AddressFamily | ConvertTo-Json')
        self.result.network_info = result.std_out.decode('utf-8')


def scan_host(host_id: int, password: str = None) -> ScanResult:
    """Convenience function to scan a host by ID."""
    host = Host.query.get(host_id)
    if not host:
        raise ValueError(f"Host {host_id} not found")
    scanner = RemoteScanner(host, password)
    return scanner.scan()
