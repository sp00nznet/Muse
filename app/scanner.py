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

            # Recent logs (general)
            self.result.recent_logs = self._ssh_exec(
                ssh,
                'journalctl -n 50 --no-pager 2>/dev/null || tail -50 /var/log/syslog 2>/dev/null || tail -50 /var/log/messages 2>/dev/null || echo "No logs available"'
            )

            # Security Events - Failed logins, auth failures, sudo usage
            self.result.security_events = self._ssh_exec(
                ssh,
                'journalctl --since "24 hours ago" -n 100 --no-pager 2>/dev/null | grep -iE "(failed|invalid user|accepted|session opened|session closed|sudo:|su:|pam_unix.*authentication)" | tail -50 || grep -iE "(failed|invalid|accepted|sudo)" /var/log/auth.log 2>/dev/null | tail -50 || echo "No security events found"'
            )

            # System Events - Service changes, reboots, shutdowns
            self.result.system_events = self._ssh_exec(
                ssh,
                'journalctl --since "7 days ago" --no-pager 2>/dev/null | grep -iE "(Started|Stopped|Reloaded|systemd\\[1\\]:|reboot|shutdown|Reached target)" | tail -50 || echo "No system events found"'
            )

            # Application Events - App crashes, errors from apps
            self.result.application_events = self._ssh_exec(
                ssh,
                'journalctl -p err --since "24 hours ago" -n 50 --no-pager 2>/dev/null || tail -50 /var/log/kern.log 2>/dev/null || echo "No application events found"'
            )

            # Hardware Events - Disk errors, hardware issues
            self.result.hardware_events = self._ssh_exec(
                ssh,
                'dmesg 2>/dev/null | grep -iE "(error|fail|warn|I/O|sector|disk|sda|sdb|nvme|hardware|temperature)" | tail -30 || echo "No hardware events found"'
            )

            # Critical Errors - High priority events
            self.result.critical_errors = self._ssh_exec(
                ssh,
                'journalctl -p crit..emerg --since "7 days ago" -n 50 --no-pager 2>/dev/null || echo "No critical errors found"'
            )

            # Recent Changes - Package installs, config changes
            self.result.recent_changes = self._ssh_exec(
                ssh,
                'tail -50 /var/log/dpkg.log 2>/dev/null || tail -50 /var/log/yum.log 2>/dev/null || tail -50 /var/log/dnf.rpm.log 2>/dev/null || journalctl --since "7 days ago" --no-pager 2>/dev/null | grep -iE "(installed|upgraded|removed|apt|yum|dnf)" | tail -30 || echo "No recent changes found"'
            )

            # Event Summary - Build a summary of notable events
            summary_parts = []
            crit_count = self._ssh_exec(ssh, 'journalctl -p crit --since "24 hours ago" --no-pager 2>/dev/null | wc -l || echo 0').strip()
            err_count = self._ssh_exec(ssh, 'journalctl -p err --since "24 hours ago" --no-pager 2>/dev/null | wc -l || echo 0').strip()
            failed_logins = self._ssh_exec(ssh, 'journalctl --since "24 hours ago" --no-pager 2>/dev/null | grep -ci "failed" 2>/dev/null || echo 0').strip()
            reboot_count = self._ssh_exec(ssh, 'last reboot 2>/dev/null | grep -c "reboot" || echo 0').strip()

            try:
                summary_parts.append(f"Critical events (24h): {int(crit_count)}")
                summary_parts.append(f"Error events (24h): {int(err_count)}")
                summary_parts.append(f"Failed auth attempts (24h): {int(failed_logins)}")
                summary_parts.append(f"Reboots recorded: {int(reboot_count)}")
            except ValueError:
                summary_parts.append("Unable to parse event counts")

            # Check for OOM killer
            oom_events = self._ssh_exec(ssh, 'dmesg 2>/dev/null | grep -c "Out of memory" || echo 0').strip()
            try:
                if oom_events and int(oom_events) > 0:
                    summary_parts.append(f"⚠️ OOM Killer invocations: {oom_events}")
            except ValueError:
                pass

            # Check disk space warnings
            disk_warn = self._ssh_exec(ssh, "df -h 2>/dev/null | awk 'NR>1 && int($5)>80 {print $6\": \"$5}' | head -5").strip()
            if disk_warn:
                summary_parts.append(f"⚠️ High disk usage: {disk_warn}")

            self.result.event_summary = '\n'.join(summary_parts) if summary_parts else "No notable events"

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

        # Recent logs (System Event Log)
        result = session.run_ps('Get-EventLog -LogName System -Newest 50 | Select-Object TimeGenerated, EntryType, Source, Message | ConvertTo-Json')
        self.result.recent_logs = result.std_out.decode('utf-8')

        # Security Events - Failed logins, audit events
        result = session.run_ps('''
            Get-WinEvent -FilterHashtable @{LogName='Security'; StartTime=(Get-Date).AddDays(-1)} -MaxEvents 100 -ErrorAction SilentlyContinue |
            Where-Object { $_.Id -in @(4625, 4624, 4634, 4648, 4672, 4768, 4769, 4771) } |
            Select-Object TimeCreated, Id, @{N='Event';E={
                switch($_.Id) {
                    4625 {'Failed Login'}
                    4624 {'Successful Login'}
                    4634 {'Logoff'}
                    4648 {'Explicit Credential Use'}
                    4672 {'Admin Login'}
                    4768 {'Kerberos TGT Request'}
                    4769 {'Kerberos Service Ticket'}
                    4771 {'Kerberos Pre-Auth Failed'}
                }
            }}, Message | Select-Object -First 50 | ConvertTo-Json
        ''')
        self.result.security_events = result.std_out.decode('utf-8') or "No security events found"

        # System Events - Service changes, shutdowns, reboots
        result = session.run_ps('''
            Get-WinEvent -FilterHashtable @{LogName='System'; StartTime=(Get-Date).AddDays(-7)} -MaxEvents 100 -ErrorAction SilentlyContinue |
            Where-Object { $_.Id -in @(6005, 6006, 6008, 6009, 7034, 7035, 7036, 7040, 1074, 41) } |
            Select-Object TimeCreated, Id, @{N='Event';E={
                switch($_.Id) {
                    6005 {'Event Log Started'}
                    6006 {'Event Log Stopped'}
                    6008 {'Unexpected Shutdown'}
                    6009 {'OS Version at Boot'}
                    7034 {'Service Crashed'}
                    7035 {'Service Control'}
                    7036 {'Service State Change'}
                    7040 {'Service Start Type Change'}
                    1074 {'Shutdown Initiated'}
                    41 {'Kernel Power Error'}
                }
            }}, Message | Select-Object -First 50 | ConvertTo-Json
        ''')
        self.result.system_events = result.std_out.decode('utf-8') or "No system events found"

        # Application Events - App crashes, errors
        result = session.run_ps('''
            Get-WinEvent -FilterHashtable @{LogName='Application'; Level=1,2; StartTime=(Get-Date).AddDays(-1)} -MaxEvents 50 -ErrorAction SilentlyContinue |
            Select-Object TimeCreated, ProviderName, LevelDisplayName, Message |
            ConvertTo-Json
        ''')
        self.result.application_events = result.std_out.decode('utf-8') or "No application events found"

        # Hardware Events - Disk errors, hardware issues
        result = session.run_ps('''
            Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName=@('disk','Microsoft-Windows-Kernel-WHEA','Microsoft-Windows-StorPort','Microsoft-Windows-Ntfs'); StartTime=(Get-Date).AddDays(-7)} -MaxEvents 30 -ErrorAction SilentlyContinue |
            Select-Object TimeCreated, ProviderName, LevelDisplayName, Message |
            ConvertTo-Json;
            Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Storage-Storport/Operational'} -MaxEvents 20 -ErrorAction SilentlyContinue |
            Select-Object TimeCreated, Message | ConvertTo-Json
        ''')
        self.result.hardware_events = result.std_out.decode('utf-8') or "No hardware events found"

        # Critical Errors - Critical and Error level events from System
        result = session.run_ps('''
            Get-WinEvent -FilterHashtable @{LogName='System'; Level=1,2; StartTime=(Get-Date).AddDays(-7)} -MaxEvents 50 -ErrorAction SilentlyContinue |
            Select-Object TimeCreated, ProviderName, LevelDisplayName, Message |
            ConvertTo-Json
        ''')
        self.result.critical_errors = result.std_out.decode('utf-8') or "No critical errors found"

        # CBS Logs - Windows Component Store logs
        result = session.run_ps('''
            $cbsLog = "$env:windir\\Logs\\CBS\\CBS.log"
            if (Test-Path $cbsLog) {
                Get-Content $cbsLog -Tail 100 | Select-String -Pattern "(Error|Warning|Failed|HRESULT)" | Select-Object -Last 50 | ForEach-Object { $_.Line }
            } else {
                "CBS log not accessible"
            }
        ''')
        self.result.cbs_logs = result.std_out.decode('utf-8') or "CBS logs not available"

        # Recent Changes - Windows Update, installed software
        result = session.run_ps('''
            $updates = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 20 HotFixID, Description, InstalledOn | ConvertTo-Json;
            $installs = Get-WinEvent -FilterHashtable @{LogName='Application'; ProviderName='MsiInstaller'; StartTime=(Get-Date).AddDays(-7)} -MaxEvents 20 -ErrorAction SilentlyContinue |
            Select-Object TimeCreated, Message | ConvertTo-Json;
            @{Updates=$updates; RecentInstalls=$installs} | ConvertTo-Json
        ''')
        self.result.recent_changes = result.std_out.decode('utf-8') or "No recent changes found"

        # Event Summary - Build a summary of notable events
        result = session.run_ps('''
            $summary = @()
            $critCount = (Get-WinEvent -FilterHashtable @{LogName='System'; Level=1; StartTime=(Get-Date).AddDays(-1)} -ErrorAction SilentlyContinue | Measure-Object).Count
            $errCount = (Get-WinEvent -FilterHashtable @{LogName='System'; Level=2; StartTime=(Get-Date).AddDays(-1)} -ErrorAction SilentlyContinue | Measure-Object).Count
            $failedLogins = (Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; StartTime=(Get-Date).AddDays(-1)} -ErrorAction SilentlyContinue | Measure-Object).Count
            $unexpectedShutdowns = (Get-WinEvent -FilterHashtable @{LogName='System'; Id=6008; StartTime=(Get-Date).AddDays(-7)} -ErrorAction SilentlyContinue | Measure-Object).Count

            $summary += "Critical events (24h): $critCount"
            $summary += "Error events (24h): $errCount"
            $summary += "Failed login attempts (24h): $failedLogins"
            $summary += "Unexpected shutdowns (7d): $unexpectedShutdowns"

            # Check disk space
            Get-WmiObject Win32_LogicalDisk | Where-Object { $_.DriveType -eq 3 } | ForEach-Object {
                $pctFree = [math]::Round(($_.FreeSpace / $_.Size) * 100, 1)
                if ($pctFree -lt 20) {
                    $summary += "⚠️ Low disk space on $($_.DeviceID): $pctFree% free"
                }
            }

            # Check for BSOD events
            $bsodCount = (Get-WinEvent -FilterHashtable @{LogName='System'; Id=1001; ProviderName='Microsoft-Windows-WER-SystemErrorReporting'; StartTime=(Get-Date).AddDays(-30)} -ErrorAction SilentlyContinue | Measure-Object).Count
            if ($bsodCount -gt 0) {
                $summary += "⚠️ Blue screen events (30d): $bsodCount"
            }

            $summary -join "`n"
        ''')
        self.result.event_summary = result.std_out.decode('utf-8') or "No notable events"

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
