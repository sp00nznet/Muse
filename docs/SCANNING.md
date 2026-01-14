# 🔍 Scanning Guide

Detailed guide on health monitoring and antivirus scanning capabilities.

---

## 🏥 Health Scanning

Health scans collect system metrics and information from remote hosts.

### How It Works

```
┌─────────────┐     SSH/WinRM      ┌─────────────────┐
│    Muse     │ ─────────────────► │   Remote Host   │
│   Server    │                    │                 │
│             │ ◄───────────────── │  Execute cmds   │
│             │    Return data     │  Return output  │
└─────────────┘                    └─────────────────┘
```

1. Muse connects to the host via SSH (Linux) or WinRM (Windows)
2. Executes system commands to gather metrics
3. Parses and stores the results
4. Updates host status

### Collected Metrics

#### 🐧 Linux Metrics

| Metric | Command | Description |
|--------|---------|-------------|
| Hostname | `hostname` | System hostname |
| OS Info | `cat /etc/os-release` | Distribution details |
| Uptime | `uptime -p` | System uptime |
| CPU Usage | `top -bn1` | Current CPU percentage |
| Memory | `free -b` | Total/used memory |
| Disk | `df -h` | Disk usage by mount |
| Users | `who` | Logged-in users |
| Processes | `ps aux` | Running processes |
| Logs | `journalctl -n 50` | Recent system logs |
| Network | `ip addr` | Network interfaces |

#### 🪟 Windows Metrics

| Metric | PowerShell Command | Description |
|--------|-------------------|-------------|
| Hostname | `hostname` | System hostname |
| OS Info | `Get-CimInstance Win32_OperatingSystem` | Windows version |
| Uptime | `LastBootUpTime` calculation | System uptime |
| CPU Usage | `Win32_Processor LoadPercentage` | Current CPU % |
| Memory | `Win32_OperatingSystem` memory | Total/free memory |
| Disk | `Get-PSDrive` | Disk usage |
| Users | `query user` | Logged-in users |
| Processes | `Get-Process` | Running processes |
| Logs | `Get-EventLog System` | System event log |
| Network | `Get-NetIPAddress` | Network interfaces |

### Understanding Results

#### CPU Usage

```
CPU Usage: 45.2%
├── 0-50%   🟢 Normal
├── 50-80%  🟡 Elevated
└── 80-100% 🔴 Critical
```

#### Memory Usage

```
Memory: 4.2 GB / 8.0 GB (52.5%)
├── 0-50%   🟢 Normal
├── 50-80%  🟡 Elevated
└── 80-100% 🔴 Critical
```

---

## 📊 Event Analysis

Health scans include comprehensive event log analysis to detect recent system activity and potential issues.

### Event Categories

| Category | Linux Source | Windows Source | Time Range |
|----------|--------------|----------------|------------|
| 🔐 Security Events | `journalctl`, `/var/log/auth.log` | Security Event Log (4625, 4624, etc.) | 24 hours |
| ⚙️ System Events | `journalctl` (systemd) | System Event Log (6005, 6008, 7036, etc.) | 7 days |
| 📱 Application Events | `journalctl -p err` | Application Event Log | 24 hours |
| 🔧 Hardware Events | `dmesg` | Disk, WHEA, StorPort logs | 7 days |
| 🚨 Critical Errors | `journalctl -p crit..emerg` | System Log (Level 1-2) | 7 days |
| 📦 Recent Changes | dpkg/yum/dnf logs | Windows Update, MsiInstaller | 7 days |
| 🪟 CBS Logs | N/A | `%windir%\Logs\CBS\CBS.log` | Recent |

### Linux Event Analysis

#### Security Events Detected
- Failed SSH login attempts
- Successful logins (accepted)
- Session open/close events
- `sudo` command usage
- `su` authentication
- PAM authentication failures

#### System Events Detected
- Service starts/stops
- System reboots
- Shutdown events
- Systemd target changes

#### Summary Metrics
```
Critical events (24h): 0
Error events (24h): 5
Failed auth attempts (24h): 12
Reboots recorded: 2
⚠️ OOM Killer invocations: 1
⚠️ High disk usage: /var: 85%
```

### Windows Event Analysis

#### Security Events (Event IDs)
| Event ID | Description |
|----------|-------------|
| 4625 | Failed Login |
| 4624 | Successful Login |
| 4634 | Logoff |
| 4648 | Explicit Credential Use |
| 4672 | Admin Login |
| 4768 | Kerberos TGT Request |
| 4769 | Kerberos Service Ticket |
| 4771 | Kerberos Pre-Auth Failed |

#### System Events (Event IDs)
| Event ID | Description |
|----------|-------------|
| 6005 | Event Log Started (boot) |
| 6006 | Event Log Stopped (shutdown) |
| 6008 | Unexpected Shutdown |
| 6009 | OS Version at Boot |
| 7034 | Service Crashed |
| 7036 | Service State Change |
| 7040 | Service Start Type Change |
| 1074 | Shutdown Initiated |
| 41 | Kernel Power Error |

#### CBS Log Analysis
Windows Component-Based Servicing logs are analyzed for:
- Update installation errors
- Component store corruption
- HRESULT error codes
- Failed Windows Update operations

#### Summary Metrics
```
Critical events (24h): 0
Error events (24h): 3
Failed login attempts (24h): 5
Unexpected shutdowns (7d): 1
⚠️ Low disk space on C:: 15.2% free
⚠️ Blue screen events (30d): 2
```

---

## 🦠 Antivirus Scanning

AV scanning fetches files from remote hosts and scans them with ClamAV.

### How It Works

```
┌─────────┐    SSH/WinRM     ┌─────────┐    Stream     ┌─────────┐
│  Muse   │ ───────────────► │ Remote  │              │ ClamAV  │
│ Server  │                  │  Host   │              │ Daemon  │
│         │ ◄─────────────── │         │              │         │
│         │   File content   │         │              │         │
│         │ ───────────────────────────────────────► │         │
│         │                  Scan stream              │         │
│         │ ◄─────────────────────────────────────── │         │
│         │                  Scan result              │         │
└─────────┘                  └─────────┘              └─────────┘
```

1. Muse connects to the remote host
2. Finds files in target directories
3. Streams each file to ClamAV daemon
4. Records any detected threats
5. Stores results in database

### Scan Types

#### ⚡ Quick Scan

Scans common malware locations. Fastest option.

**Linux paths:**
- `/tmp`
- `/var/tmp`
- `/home`
- `/root`
- `/var/www`

**Windows paths:**
- `C:\Users`
- `C:\Windows\Temp`
- `C:\Temp`

#### 🔍 Full Scan

More comprehensive scan including application directories.

**Linux paths:**
- All quick scan paths, plus:
- `/opt`
- `/usr/local/bin`
- `/var/log`

**Windows paths:**
- All quick scan paths, plus:
- `C:\ProgramData`
- `C:\Program Files`
- `C:\Program Files (x86)`

#### 🎯 Custom Scan

Specify your own paths to scan.

```
/var/www/html
/home/deploy/apps
/opt/custom-app
```

### Scan Limits

| Limit | Value | Purpose |
|-------|-------|---------|
| Max file size | 10 MB | Prevent memory issues |
| Max files per directory | 500 | Prevent runaway scans |
| Timeout per directory | 60 seconds | Prevent hanging |

### Understanding Results

#### Clean Scan

```
✅ AV Scan Complete
   Files scanned: 1,523
   Threats found: 0
   Duration: 2m 15s
```

#### Threats Detected

```
⚠️ Threats Detected!
   Files scanned: 1,523
   Threats found: 2

   Threat Details:
   /tmp/suspicious.exe: Win.Trojan.Generic-123456
   /var/www/uploads/malware.php: Php.Malware.Agent-789012
```

### Common Threats

| Threat Type | Description | Action |
|-------------|-------------|--------|
| `Trojan.*` | Trojan horse malware | Quarantine & investigate |
| `Backdoor.*` | Remote access backdoor | Immediate removal |
| `Php.Malware.*` | PHP webshell | Check web uploads |
| `Crypto.*` | Cryptocurrency miner | Check for compromise |
| `PUA.*` | Potentially unwanted app | Review necessity |

---

## 🔧 Troubleshooting Scans

### Health Scan Failures

#### "Connection refused"

```bash
# Linux: Check SSH is running
systemctl status sshd

# Windows: Check WinRM
winrm enumerate winrm/config/listener
```

#### "Authentication failed"

- Verify username/password
- Check SSH key format (PEM)
- Ensure user has sudo/admin rights

#### "Permission denied"

```bash
# Linux: Check user permissions
sudo -l -U scanuser

# May need to run certain commands as root
```

### AV Scan Failures

#### "Cannot connect to ClamAV daemon"

```bash
# Check ClamAV is running
docker-compose ps clamav

# Check logs
docker-compose logs clamav

# Restart if needed
docker-compose restart clamav
```

#### "Scan timeout"

- Reduce scan scope (use quick scan)
- Check network latency
- Increase timeout in scanner.py

#### "No files scanned"

- Verify paths exist on remote host
- Check user has read permissions
- Ensure files are under 10MB

---

## 📋 Best Practices

### Scheduling Scans

1. **Health scans:** Run every 5-15 minutes
2. **Quick AV scans:** Run daily
3. **Full AV scans:** Run weekly

### Security Considerations

1. ✅ Use SSH keys instead of passwords
2. ✅ Create dedicated scan user with minimal permissions
3. ✅ Restrict network access to scan ports
4. ✅ Review scan results regularly
5. ✅ Keep ClamAV definitions updated

### Performance Tips

1. Stagger scans across hosts
2. Use quick scans for routine checks
3. Schedule full scans during off-hours
4. Monitor ClamAV memory usage

---

## 🔄 Scan Workflow Example

### Daily Routine

```
06:00 - Full AV scan (all hosts)
       └─ Review any threats

09:00 - Health scan (all hosts)
12:00 - Health scan (all hosts)
15:00 - Health scan (all hosts)
18:00 - Health scan (all hosts)
       └─ Daily report

22:00 - Quick AV scan (web servers)
       └─ Check upload directories
```

### Incident Response

```
1. 🚨 Alert received
2. 🔍 Run full AV scan on affected host
3. 📊 Review health metrics for anomalies
4. 🔒 Isolate if threats found
5. 🧹 Clean and verify
6. ✅ Re-scan to confirm
```

---

[← Back to README](../README.md)
