import os
import io
import tempfile
import tarfile
from datetime import datetime
from typing import Optional, List, Dict
import pyclamd
import paramiko
import winrm
from app import db
from app.models import Host, AVScanResult


class ClamAVScanner:
    """Scanner that fetches files from remote hosts and scans with ClamAV."""

    def __init__(self, host: Host, password: str = None):
        self.host = host
        self.password = password or host.password_encrypted
        self.clamav_host = os.environ.get('CLAMAV_HOST', 'clamav')
        self.clamav_port = int(os.environ.get('CLAMAV_PORT', 3310))
        self.clam = None

    def _connect_clamav(self):
        """Connect to ClamAV daemon."""
        self.clam = pyclamd.ClamdNetworkSocket(
            host=self.clamav_host,
            port=self.clamav_port
        )
        if not self.clam.ping():
            raise ConnectionError("Cannot connect to ClamAV daemon")

    def scan(self, paths: List[str] = None, scan_type: str = 'quick') -> 'AVScanResult':
        """
        Scan remote host for malware.

        Args:
            paths: Specific paths to scan. If None, uses default paths based on scan_type.
            scan_type: 'quick' (common malware locations), 'full' (more comprehensive),
                      'custom' (user-specified paths)
        """
        result = AVScanResult(
            host_id=self.host.id,
            scan_type=scan_type,
            paths_scanned=','.join(paths) if paths else ''
        )

        try:
            self._connect_clamav()

            if self.host.os_type == 'windows':
                scan_results = self._scan_windows(paths, scan_type)
            else:
                scan_results = self._scan_linux(paths, scan_type)

            result.success = True
            result.files_scanned = scan_results.get('files_scanned', 0)
            result.threats_found = scan_results.get('threats_found', 0)
            result.threat_details = scan_results.get('threat_details', '')
            result.scan_summary = scan_results.get('summary', '')

            if result.threats_found > 0:
                self.host.status = 'warning'

        except Exception as e:
            result.success = False
            result.error_message = str(e)

        result.completed_at = datetime.utcnow()
        db.session.add(result)
        db.session.commit()
        return result

    def _get_linux_paths(self, scan_type: str) -> List[str]:
        """Get default scan paths for Linux."""
        if scan_type == 'quick':
            return [
                '/tmp',
                '/var/tmp',
                '/home',
                '/root',
                '/var/www',
            ]
        else:  # full
            return [
                '/tmp',
                '/var/tmp',
                '/home',
                '/root',
                '/var/www',
                '/opt',
                '/usr/local/bin',
                '/var/log',
            ]

    def _get_windows_paths(self, scan_type: str) -> List[str]:
        """Get default scan paths for Windows."""
        if scan_type == 'quick':
            return [
                'C:\\Users',
                'C:\\Windows\\Temp',
                'C:\\Temp',
            ]
        else:  # full
            return [
                'C:\\Users',
                'C:\\Windows\\Temp',
                'C:\\Temp',
                'C:\\ProgramData',
                'C:\\Program Files',
                'C:\\Program Files (x86)',
            ]

    def _scan_linux(self, paths: List[str], scan_type: str) -> Dict:
        """Scan Linux host via SSH, fetching files and scanning with ClamAV."""
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

        scan_paths = paths if paths else self._get_linux_paths(scan_type)
        files_scanned = 0
        threats_found = 0
        threat_details = []
        scanned_paths = []

        try:
            ssh.connect(**connect_kwargs)
            sftp = ssh.open_sftp()

            for path in scan_paths:
                try:
                    # Check if path exists
                    stdin, stdout, stderr = ssh.exec_command(f'test -e {path} && echo "exists"')
                    if 'exists' not in stdout.read().decode():
                        continue

                    scanned_paths.append(path)

                    # Find files (limit to reasonable size and count)
                    cmd = f'find {path} -type f -size -10M 2>/dev/null | head -500'
                    stdin, stdout, stderr = ssh.exec_command(cmd, timeout=60)
                    files = stdout.read().decode().strip().split('\n')
                    files = [f for f in files if f]

                    for filepath in files:
                        try:
                            # Fetch file content
                            with sftp.open(filepath, 'rb') as remote_file:
                                content = remote_file.read(10 * 1024 * 1024)  # Max 10MB

                            files_scanned += 1

                            # Scan with ClamAV
                            scan_result = self.clam.scan_stream(content)
                            if scan_result:
                                threats_found += 1
                                status, virus_name = list(scan_result.values())[0]
                                threat_details.append(f"{filepath}: {virus_name}")

                        except (IOError, PermissionError):
                            continue
                        except Exception:
                            continue

                except Exception:
                    continue

            sftp.close()

        finally:
            ssh.close()

        return {
            'files_scanned': files_scanned,
            'threats_found': threats_found,
            'threat_details': '\n'.join(threat_details) if threat_details else 'No threats detected',
            'summary': f"Scanned {files_scanned} files in {len(scanned_paths)} directories. Found {threats_found} threat(s)."
        }

    def _scan_windows(self, paths: List[str], scan_type: str) -> Dict:
        """Scan Windows host via WinRM, fetching files and scanning with ClamAV."""
        session = winrm.Session(
            f'http://{self.host.ip_address or self.host.hostname}:{self.host.winrm_port}/wsman',
            auth=(self.host.username, self.password),
            transport='ntlm'
        )

        scan_paths = paths if paths else self._get_windows_paths(scan_type)
        files_scanned = 0
        threats_found = 0
        threat_details = []
        scanned_paths = []

        for path in scan_paths:
            try:
                # Check if path exists and get files
                ps_cmd = f'''
                if (Test-Path "{path}") {{
                    Get-ChildItem -Path "{path}" -Recurse -File -ErrorAction SilentlyContinue |
                    Where-Object {{ $_.Length -lt 10MB }} |
                    Select-Object -First 500 -ExpandProperty FullName
                }}
                '''
                result = session.run_ps(ps_cmd)
                if result.status_code != 0:
                    continue

                scanned_paths.append(path)
                files = result.std_out.decode('utf-8').strip().split('\r\n')
                files = [f for f in files if f]

                for filepath in files:
                    try:
                        # Fetch file content via PowerShell
                        ps_read = f'[Convert]::ToBase64String([IO.File]::ReadAllBytes("{filepath}"))'
                        result = session.run_ps(ps_read)
                        if result.status_code != 0:
                            continue

                        import base64
                        content = base64.b64decode(result.std_out.decode('utf-8').strip())
                        files_scanned += 1

                        # Scan with ClamAV
                        scan_result = self.clam.scan_stream(content)
                        if scan_result:
                            threats_found += 1
                            status, virus_name = list(scan_result.values())[0]
                            threat_details.append(f"{filepath}: {virus_name}")

                    except Exception:
                        continue

            except Exception:
                continue

        return {
            'files_scanned': files_scanned,
            'threats_found': threats_found,
            'threat_details': '\n'.join(threat_details) if threat_details else 'No threats detected',
            'summary': f"Scanned {files_scanned} files in {len(scanned_paths)} directories. Found {threats_found} threat(s)."
        }


def scan_host_av(host_id: int, password: str = None, paths: List[str] = None,
                 scan_type: str = 'quick') -> AVScanResult:
    """Convenience function to run AV scan on a host by ID."""
    host = Host.query.get(host_id)
    if not host:
        raise ValueError(f"Host {host_id} not found")
    scanner = ClamAVScanner(host, password)
    return scanner.scan(paths=paths, scan_type=scan_type)
