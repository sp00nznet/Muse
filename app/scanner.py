import io
import json
from datetime import datetime
import paramiko
import winrm
from cryptography.fernet import Fernet
import os
from app import db
from app.models import Host, ScanResult, ServiceAccount


def get_encryption_key():
    """Get encryption key for decrypting service account passwords."""
    key = os.environ.get('MUSE_ENCRYPTION_KEY')
    if not key:
        key = Fernet.generate_key().decode()
        os.environ['MUSE_ENCRYPTION_KEY'] = key
    return key.encode() if isinstance(key, str) else key


def decrypt_value(encrypted_value: str) -> str:
    """Decrypt a sensitive value."""
    if not encrypted_value:
        return None
    try:
        f = Fernet(get_encryption_key())
        return f.decrypt(encrypted_value.encode()).decode()
    except Exception:
        return encrypted_value  # Return as-is if not encrypted


class RemoteScanner:
    """Scanner for remote host metrics via SSH or WinRM."""

    def __init__(self, host: Host, password: str = None):
        self.host = host
        self.result = ScanResult(host_id=host.id)

        # Determine credentials to use
        self.username = None
        self.password = None
        self.ssh_key = None
        self.ssh_key_passphrase = None
        self.domain = None

        # Check if host uses a service account
        if host.use_service_account and host.service_account_id:
            service_account = ServiceAccount.query.get(host.service_account_id)
            if service_account and service_account.is_active:
                self.username = service_account.username
                self.password = decrypt_value(service_account.password_encrypted)
                self.ssh_key = decrypt_value(service_account.ssh_key_encrypted)
                self.ssh_key_passphrase = decrypt_value(service_account.ssh_key_passphrase_encrypted)
                self.domain = service_account.domain
            else:
                # Fall back to host credentials if service account is invalid
                self.username = host.username
                self.password = password or host.password_encrypted
                self.ssh_key = host.ssh_key
        else:
            # Use host-level credentials
            self.username = host.username
            self.password = password or host.password_encrypted
            self.ssh_key = host.ssh_key

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
            'username': self.username,
            'timeout': 30
        }

        if self.ssh_key:
            key_file = io.StringIO(self.ssh_key)
            try:
                private_key = paramiko.RSAKey.from_private_key(
                    key_file,
                    password=self.ssh_key_passphrase
                )
            except paramiko.ssh_exception.SSHException:
                # Try other key types
                key_file.seek(0)
                try:
                    private_key = paramiko.Ed25519Key.from_private_key(
                        key_file,
                        password=self.ssh_key_passphrase
                    )
                except paramiko.ssh_exception.SSHException:
                    key_file.seek(0)
                    private_key = paramiko.ECDSAKey.from_private_key(
                        key_file,
                        password=self.ssh_key_passphrase
                    )
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

            # =========================================================
            # SYSTEM UPDATES & PACKAGE INFO
            # =========================================================

            # Pending Updates - Check for available updates
            self.result.pending_updates = self._ssh_exec(
                ssh,
                '''
                if command -v apt-get &>/dev/null; then
                    apt-get -s upgrade 2>/dev/null | grep -E "^Inst" | head -50
                elif command -v yum &>/dev/null; then
                    yum check-update 2>/dev/null | tail -50
                elif command -v dnf &>/dev/null; then
                    dnf check-update 2>/dev/null | tail -50
                elif command -v zypper &>/dev/null; then
                    zypper list-updates 2>/dev/null | head -50
                else
                    echo "Unknown package manager"
                fi
                '''
            )

            # Update History - Recent package updates
            self.result.update_history = self._ssh_exec(
                ssh,
                '''
                if [ -f /var/log/apt/history.log ]; then
                    grep -E "^(Start-Date|Commandline|Upgrade|Install)" /var/log/apt/history.log | tail -100
                elif [ -f /var/log/dpkg.log ]; then
                    grep -E "(install|upgrade)" /var/log/dpkg.log | tail -50
                elif [ -f /var/log/yum.log ]; then
                    tail -50 /var/log/yum.log
                elif [ -f /var/log/dnf.rpm.log ]; then
                    tail -50 /var/log/dnf.rpm.log
                else
                    journalctl --since "30 days ago" --no-pager 2>/dev/null | grep -iE "(apt|yum|dnf|installed|upgraded)" | tail -50 || echo "No update history found"
                fi
                '''
            )

            # Last Update Check
            self.result.last_update_check = self._ssh_exec(
                ssh,
                '''
                if [ -f /var/lib/apt/periodic/update-success-stamp ]; then
                    stat -c %y /var/lib/apt/periodic/update-success-stamp 2>/dev/null
                elif [ -f /var/cache/apt/pkgcache.bin ]; then
                    stat -c %y /var/cache/apt/pkgcache.bin 2>/dev/null
                elif [ -f /var/cache/yum/timedhosts ]; then
                    stat -c %y /var/cache/yum/timedhosts 2>/dev/null
                elif [ -f /var/cache/dnf/last_makecache ]; then
                    cat /var/cache/dnf/last_makecache 2>/dev/null
                else
                    echo "Unknown"
                fi
                '''
            ).strip()

            # =========================================================
            # DRIVER INFORMATION
            # =========================================================

            # Driver Info - Loaded kernel modules with versions
            self.result.driver_info = self._ssh_exec(
                ssh,
                '''
                echo "=== Loaded Kernel Modules ==="
                lsmod | head -50
                echo ""
                echo "=== Key Driver Versions ==="
                for mod in $(lsmod | awk 'NR>1 {print $1}' | head -20); do
                    modinfo $mod 2>/dev/null | grep -E "^(filename|version|description):" | head -3
                    echo "---"
                done 2>/dev/null | head -100
                '''
            )

            # Driver Updates - Check for firmware/driver updates
            self.result.driver_updates = self._ssh_exec(
                ssh,
                '''
                if command -v fwupdmgr &>/dev/null; then
                    echo "=== Firmware Updates Available ==="
                    fwupdmgr get-updates 2>/dev/null | head -30 || echo "No firmware updates"
                fi
                if command -v ubuntu-drivers &>/dev/null; then
                    echo "=== Recommended Drivers ==="
                    ubuntu-drivers list 2>/dev/null || echo "No driver recommendations"
                fi
                '''
            )

            # =========================================================
            # BUILD & VERSION INFO
            # =========================================================

            # Kernel Version
            self.result.kernel_version = self._ssh_exec(ssh, 'uname -r').strip()

            # Build Info - Detailed version information
            self.result.build_info = self._ssh_exec(
                ssh,
                '''
                echo "=== OS Release ==="
                cat /etc/os-release 2>/dev/null || cat /etc/*-release 2>/dev/null | head -20
                echo ""
                echo "=== Kernel Details ==="
                uname -a
                echo ""
                echo "=== LSB Release ==="
                lsb_release -a 2>/dev/null || echo "LSB not available"
                echo ""
                echo "=== Build Date ==="
                stat -c %y /boot/vmlinuz-$(uname -r) 2>/dev/null || echo "Unknown"
                '''
            )

            # Installed Packages - Key packages and their versions
            self.result.installed_packages = self._ssh_exec(
                ssh,
                '''
                if command -v dpkg &>/dev/null; then
                    echo "=== Key Packages (dpkg) ==="
                    dpkg -l | grep -E "^ii" | awk '{print $2, $3}' | grep -E "(linux-image|openssh|nginx|apache|mysql|postgres|docker|python|node|java|php)" | head -30
                    echo ""
                    echo "=== Total Packages ==="
                    dpkg -l | grep -c "^ii"
                elif command -v rpm &>/dev/null; then
                    echo "=== Key Packages (rpm) ==="
                    rpm -qa --qf "%{NAME} %{VERSION}-%{RELEASE}\n" | grep -E "(kernel|openssh|nginx|httpd|mysql|postgres|docker|python|node|java|php)" | head -30
                    echo ""
                    echo "=== Total Packages ==="
                    rpm -qa | wc -l
                fi
                '''
            )

            # =========================================================
            # SYSTEM SNAPSHOT FOR COMPARISON
            # =========================================================

            # Create a JSON snapshot for easy comparison
            snapshot_data = {
                'hostname': self.result.hostname_reported,
                'os_type': 'linux',
                'kernel_version': self.result.kernel_version,
                'cpu_usage': self.result.cpu_usage,
                'memory_percent': self.result.memory_percent,
                'memory_total_gb': round(self.result.memory_total / (1024**3), 2) if self.result.memory_total else None,
                'process_count': self.result.process_count,
                'uptime': self.result.uptime,
                'pending_update_count': len([l for l in (self.result.pending_updates or '').split('\n') if l.strip() and l.startswith('Inst')]),
                'scan_time': datetime.utcnow().isoformat()
            }

            # Extract distro info
            os_info = self.result.os_info or ''
            for line in os_info.split('\n'):
                if line.startswith('PRETTY_NAME='):
                    snapshot_data['os_pretty_name'] = line.split('=', 1)[1].strip('"')
                elif line.startswith('VERSION_ID='):
                    snapshot_data['os_version'] = line.split('=', 1)[1].strip('"')

            self.result.system_snapshot = json.dumps(snapshot_data)

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
        # Build username - include domain if using domain credentials
        if self.domain:
            auth_username = f"{self.domain}\\{self.username}"
        else:
            auth_username = self.username

        session = winrm.Session(
            f'http://{self.host.ip_address or self.host.hostname}:{self.host.winrm_port}/wsman',
            auth=(auth_username, self.password),
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

        # =========================================================
        # SYSTEM UPDATES & PACKAGE INFO (Windows)
        # =========================================================

        # Pending Updates - Check Windows Update for available updates
        result = session.run_ps('''
            $UpdateSession = New-Object -ComObject Microsoft.Update.Session
            $UpdateSearcher = $UpdateSession.CreateUpdateSearcher()
            try {
                $SearchResult = $UpdateSearcher.Search("IsInstalled=0")
                $Updates = @()
                foreach ($Update in $SearchResult.Updates) {
                    $Updates += @{
                        Title = $Update.Title
                        KB = ($Update.KBArticleIDs -join ", ")
                        Severity = $Update.MsrcSeverity
                        Size = [math]::Round($Update.MaxDownloadSize / 1MB, 2)
                        Categories = ($Update.Categories | ForEach-Object { $_.Name }) -join ", "
                    }
                }
                @{
                    PendingCount = $SearchResult.Updates.Count
                    Updates = $Updates | Select-Object -First 30
                } | ConvertTo-Json -Depth 3
            } catch {
                @{ Error = $_.Exception.Message; PendingCount = 0 } | ConvertTo-Json
            }
        ''')
        self.result.pending_updates = result.std_out.decode('utf-8')

        # Update History - Recent Windows Updates
        result = session.run_ps('''
            $Session = New-Object -ComObject Microsoft.Update.Session
            $Searcher = $Session.CreateUpdateSearcher()
            $HistoryCount = $Searcher.GetTotalHistoryCount()
            $History = $Searcher.QueryHistory(0, [Math]::Min($HistoryCount, 50))
            $History | Select-Object @{N='Date';E={$_.Date}},
                @{N='Title';E={$_.Title}},
                @{N='Result';E={
                    switch($_.ResultCode) {
                        1 {'In Progress'}
                        2 {'Succeeded'}
                        3 {'Succeeded With Errors'}
                        4 {'Failed'}
                        5 {'Aborted'}
                        default {'Unknown'}
                    }
                }},
                @{N='KB';E={
                    if ($_.Title -match 'KB(\d+)') { $Matches[1] } else { '' }
                }} | ConvertTo-Json
        ''')
        self.result.update_history = result.std_out.decode('utf-8')

        # Last Update Check
        result = session.run_ps('''
            $AutoUpdate = (New-Object -ComObject Microsoft.Update.AutoUpdate)
            @{
                LastSearchSuccess = $AutoUpdate.Results.LastSearchSuccessDate
                LastInstallSuccess = $AutoUpdate.Results.LastInstallationSuccessDate
            } | ConvertTo-Json
        ''')
        self.result.last_update_check = result.std_out.decode('utf-8')

        # =========================================================
        # DRIVER INFORMATION (Windows)
        # =========================================================

        # Driver Info - Installed drivers with versions
        result = session.run_ps('''
            Get-WmiObject Win32_PnPSignedDriver |
            Where-Object { $_.DeviceName -ne $null } |
            Select-Object DeviceName, DriverVersion, DriverDate, Manufacturer, DriverProviderName |
            Sort-Object DeviceName |
            Select-Object -First 50 |
            ConvertTo-Json
        ''')
        self.result.driver_info = result.std_out.decode('utf-8')

        # Driver Updates - Check for driver updates via Windows Update
        result = session.run_ps('''
            $UpdateSession = New-Object -ComObject Microsoft.Update.Session
            $UpdateSearcher = $UpdateSession.CreateUpdateSearcher()
            try {
                $SearchResult = $UpdateSearcher.Search("IsInstalled=0 AND Type='Driver'")
                $DriverUpdates = @()
                foreach ($Update in $SearchResult.Updates) {
                    $DriverUpdates += @{
                        Title = $Update.Title
                        DriverClass = $Update.DriverClass
                        DriverManufacturer = $Update.DriverManufacturer
                        DriverModel = $Update.DriverModel
                        DriverVerDate = $Update.DriverVerDate
                    }
                }
                @{
                    AvailableDriverUpdates = $SearchResult.Updates.Count
                    Drivers = $DriverUpdates | Select-Object -First 20
                } | ConvertTo-Json -Depth 3
            } catch {
                @{ Error = $_.Exception.Message } | ConvertTo-Json
            }
        ''')
        self.result.driver_updates = result.std_out.decode('utf-8')

        # =========================================================
        # BUILD & VERSION INFO (Windows)
        # =========================================================

        # Kernel/NT Version
        result = session.run_ps('[System.Environment]::OSVersion.Version.ToString()')
        self.result.kernel_version = result.std_out.decode('utf-8').strip()

        # Build Info - Detailed Windows version information
        result = session.run_ps('''
            $OS = Get-CimInstance Win32_OperatingSystem
            $CS = Get-CimInstance Win32_ComputerSystem
            @{
                Caption = $OS.Caption
                Version = $OS.Version
                BuildNumber = $OS.BuildNumber
                OSArchitecture = $OS.OSArchitecture
                ServicePackMajorVersion = $OS.ServicePackMajorVersion
                InstallDate = $OS.InstallDate
                LastBootUpTime = $OS.LastBootUpTime
                RegisteredUser = $OS.RegisteredUser
                SystemDirectory = $OS.SystemDirectory
                WindowsDirectory = $OS.WindowsDirectory
                Manufacturer = $CS.Manufacturer
                Model = $CS.Model
                SystemType = $CS.SystemType
                NumberOfProcessors = $CS.NumberOfProcessors
                NumberOfLogicalProcessors = $CS.NumberOfLogicalProcessors
                TotalPhysicalMemoryGB = [math]::Round($CS.TotalPhysicalMemory / 1GB, 2)
                Domain = $CS.Domain
                PartOfDomain = $CS.PartOfDomain
                CurrentTimeZone = (Get-TimeZone).DisplayName
                UBR = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -ErrorAction SilentlyContinue).UBR
                DisplayVersion = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -ErrorAction SilentlyContinue).DisplayVersion
                ReleaseId = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -ErrorAction SilentlyContinue).ReleaseId
            } | ConvertTo-Json
        ''')
        self.result.build_info = result.std_out.decode('utf-8')

        # Installed Features/Roles
        result = session.run_ps('''
            $features = @()
            # Windows Server Roles
            if (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue) {
                $features += Get-WindowsFeature | Where-Object {$_.Installed} | Select-Object Name, DisplayName | ConvertTo-Json
            }
            # Windows Optional Features (Desktop)
            else {
                Get-WindowsOptionalFeature -Online | Where-Object {$_.State -eq "Enabled"} |
                Select-Object FeatureName, State | Select-Object -First 30 | ConvertTo-Json
            }
        ''')
        self.result.installed_packages = result.std_out.decode('utf-8')

        # =========================================================
        # SYSTEM SNAPSHOT FOR COMPARISON (Windows)
        # =========================================================

        # Parse build info for snapshot
        try:
            build_data = json.loads(self.result.build_info) if self.result.build_info else {}
        except json.JSONDecodeError:
            build_data = {}

        # Parse pending updates count
        try:
            pending_data = json.loads(self.result.pending_updates) if self.result.pending_updates else {}
            pending_count = pending_data.get('PendingCount', 0)
        except json.JSONDecodeError:
            pending_count = 0

        snapshot_data = {
            'hostname': self.result.hostname_reported,
            'os_type': 'windows',
            'os_pretty_name': build_data.get('Caption', 'Windows'),
            'os_version': build_data.get('DisplayVersion') or build_data.get('ReleaseId', ''),
            'build_number': build_data.get('BuildNumber', ''),
            'ubr': build_data.get('UBR', ''),
            'full_build': f"{build_data.get('BuildNumber', '')}.{build_data.get('UBR', '')}",
            'kernel_version': self.result.kernel_version,
            'cpu_usage': self.result.cpu_usage,
            'memory_percent': self.result.memory_percent,
            'memory_total_gb': build_data.get('TotalPhysicalMemoryGB'),
            'process_count': self.result.process_count,
            'uptime': self.result.uptime,
            'pending_update_count': pending_count,
            'manufacturer': build_data.get('Manufacturer', ''),
            'model': build_data.get('Model', ''),
            'domain': build_data.get('Domain', ''),
            'scan_time': datetime.utcnow().isoformat()
        }

        self.result.system_snapshot = json.dumps(snapshot_data)


def scan_host(host_id: int, password: str = None) -> ScanResult:
    """Convenience function to scan a host by ID."""
    host = Host.query.get(host_id)
    if not host:
        raise ValueError(f"Host {host_id} not found")
    scanner = RemoteScanner(host, password)
    return scanner.scan()
