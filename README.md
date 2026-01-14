<p align="center">
  <h1 align="center">🎭 Muse</h1>
  <p align="center">
    <strong>Remote Server Observability & Security Platform</strong>
  </p>
  <p align="center">
    Monitor health metrics and scan for malware across your infrastructure
  </p>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.11+-blue?logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/flask-3.0-green?logo=flask&logoColor=white" alt="Flask">
  <img src="https://img.shields.io/badge/docker-ready-2496ED?logo=docker&logoColor=white" alt="Docker">
  <img src="https://img.shields.io/badge/ClamAV-integrated-red?logo=clamav&logoColor=white" alt="ClamAV">
</p>

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🖥️ **Health Monitoring** | CPU, memory, disk, processes, uptime, and more |
| 🦠 **Antivirus Scanning** | Integrated ClamAV for remote malware detection |
| 🔄 **Update Tracking** | Windows Update & APT/YUM package update status |
| 🔧 **Driver Management** | View installed drivers and available updates |
| 🔀 **Server Comparison** | Compare multiple servers side-by-side |
| 📋 **At-a-Glance Summaries** | Quick overview of all hosts with health indicators |
| 🐧 **Linux Support** | Connect via SSH with password or key authentication |
| 🪟 **Windows Support** | Connect via WinRM for Windows servers |
| 🔐 **User Authentication** | Secure login with session management |
| 🏢 **Domain Integration** | Connect to Active Directory for user authentication |
| 🔑 **Service Accounts** | Centralized credential management for host connections |
| 🐕 **Datadog Integration** | Pull and display host information from Datadog |
| 📊 **Dashboard** | Real-time overview of all monitored hosts |
| 🔌 **REST API** | Full API for automation and integration |
| 🐳 **Containerized** | Docker Compose for easy deployment |

---

## 🚀 Quick Start

### Prerequisites

- Docker & Docker Compose
- Git

### One-Command Deploy

```bash
git clone https://github.com/yourusername/muse.git
cd muse
docker-compose up -d
```

🌐 Open **http://localhost:5050** and create your first account!

> 💡 The first registered user automatically becomes an admin.

---

## 📸 Screenshots

```
┌─────────────────────────────────────────────────────────────┐
│  🎭 Muse                              Dashboard | Add Host  │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│   ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐         │
│   │    5    │ │    3    │ │    1    │ │    1    │         │
│   │  Total  │ │ Online  │ │ Offline │ │  Error  │         │
│   └─────────┘ └─────────┘ └─────────┘ └─────────┘         │
│                                                             │
│   Hostname        IP            OS       Status    Actions  │
│   ─────────────────────────────────────────────────────────│
│   web-server-01   192.168.1.10  🐧 linux  🟢 online  [Scan] │
│   db-server-01    192.168.1.20  🐧 linux  🟢 online  [Scan] │
│   win-server-01   192.168.1.30  🪟 windows 🟢 online [Scan] │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## 🔍 What Gets Scanned

### 🏥 Health Scan

| Metric | Linux | Windows |
|--------|:-----:|:-------:|
| CPU Usage | ✅ | ✅ |
| Memory Usage | ✅ | ✅ |
| Disk Space | ✅ | ✅ |
| Running Processes | ✅ | ✅ |
| Logged-in Users | ✅ | ✅ |
| OS Information | ✅ | ✅ |
| Uptime | ✅ | ✅ |
| Network Interfaces | ✅ | ✅ |
| System Logs | ✅ | ✅ |

### 🔄 Update & Driver Information

| Metric | Linux | Windows |
|--------|:-----:|:-------:|
| Pending Updates | ✅ APT/YUM/DNF | ✅ Windows Update |
| Update History | ✅ | ✅ |
| Last Update Check | ✅ | ✅ |
| Installed Drivers | ✅ Kernel modules | ✅ PnP drivers |
| Driver Updates Available | ✅ fwupd | ✅ Windows Update |
| Kernel/Build Version | ✅ | ✅ |
| OS Build Info | ✅ | ✅ |
| Installed Packages | ✅ | ✅ Features/Roles |

### 📊 Event Log Analysis

| Event Type | Linux | Windows |
|------------|:-----:|:-------:|
| Security Events | ✅ journalctl/auth.log | ✅ Security Event Log |
| System Events | ✅ Service changes, reboots | ✅ System Event Log |
| Application Errors | ✅ | ✅ Application Event Log |
| Hardware Events | ✅ dmesg | ✅ Hardware logs |
| Critical Errors | ✅ | ✅ |

### 🦠 Antivirus Scan

| Scan Type | Description |
|-----------|-------------|
| **Quick** | Common malware locations (`/tmp`, `/home`, `C:\Users`) |
| **Full** | Comprehensive scan including application directories |
| **Custom** | User-defined paths |

---

## 🔀 Server Comparison

Easily compare two or more servers side-by-side to identify differences:

```
┌────────────────────────────────────────────────────────────────────────┐
│  Compare: web-server-01 vs web-server-02                               │
├────────────────────────────────────────────────────────────────────────┤
│                                                                        │
│  Metric              web-server-01        web-server-02      Match?    │
│  ────────────────────────────────────────────────────────────────────  │
│  OS Version          Ubuntu 22.04         Ubuntu 22.04       ✅        │
│  Kernel              5.15.0-91-generic    5.15.0-89-generic  ⚠️        │
│  CPU Usage           23.5%                45.2%              ✅        │
│  Memory              45.2%                78.3%              ⚠️        │
│  Pending Updates     5                    23                 ❌        │
│  Event Errors (24h)  2                    15                 ⚠️        │
│                                                                        │
│  ⚠️ Differences detected: kernel_version, pending_updates             │
│                                                                        │
└────────────────────────────────────────────────────────────────────────┘
```

### Comparison Features

- **Side-by-side host comparison** - Compare OS, kernel, build info
- **Event log comparison** - Check if servers have similar error patterns
- **Update status comparison** - See which servers need patching
- **Driver comparison** - Compare driver versions across Windows servers
- **Automatic difference detection** - Highlights mismatches automatically

---

## 🔑 Service Accounts & Domain Integration

Muse provides centralized credential management through service accounts and Active Directory integration.

### Service Accounts

Manage credentials centrally instead of storing them per-host:

| Account Type | Description | Use Case |
|--------------|-------------|----------|
| `windows_domain` | Domain credentials for Windows | WinRM with domain authentication |
| `linux_password` | Username/password for Linux | SSH password authentication |
| `linux_key` | SSH key for Linux | SSH key-based authentication |

**Features:**
- Centralized credential storage with encryption
- Assign one service account to multiple hosts
- Test credentials before deployment
- Set default accounts per OS type

### Domain Controller Integration

Connect Muse to your Active Directory for user authentication:

```
┌─────────────┐      LDAP/LDAPS      ┌─────────────────┐
│    Muse     │ ◄──────────────────► │ Domain Controller│
│   Web App   │                      │   (AD/LDAP)      │
└─────────────┘                      └─────────────────┘
       │
       │ Users authenticate with
       │ domain credentials
       ▼
  ┌──────────┐
  │  Users   │
  └──────────┘
```

**Features:**
- Multiple domain controller support with failover
- AD group-based access control (admin/user groups)
- Auto-provisioning of domain users
- Support for LDAP, LDAPS, and StartTLS
- Test connections before enabling

### Admin Panel Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET/POST /api/admin/service-accounts` | Manage service accounts |
| `GET/POST /api/admin/domain-controllers` | Manage domain controllers |
| `GET/PUT /api/admin/auth-settings` | Configure authentication |
| `PUT /api/admin/hosts/{id}/service-account` | Assign service account to host |
| `POST /api/admin/hosts/bulk-assign-service-account` | Bulk assign to multiple hosts |
| `GET/POST /api/admin/datadog/integrations` | Manage Datadog integrations |
| `POST /api/admin/datadog/integrations/{id}/sync` | Sync hosts from Datadog |

---

## 🐕 Datadog Integration

Muse can pull host information from your Datadog account and display it alongside your directly-managed hosts.

### Features

- **Multi-account support** - Connect multiple Datadog accounts
- **Automatic sync** - Configurable sync intervals (default 15 min)
- **Host filtering** - Use Datadog query syntax to filter hosts
- **Cloud provider detection** - AWS, Azure, GCP metadata extraction
- **Link to Muse hosts** - Associate Datadog hosts with Muse-managed hosts

### Supported Datadog Sites

| Site | Region |
|------|--------|
| `datadoghq.com` | US1 (default) |
| `datadoghq.eu` | EU |
| `us3.datadoghq.com` | US3 |
| `us5.datadoghq.com` | US5 |
| `ap1.datadoghq.com` | AP1 |
| `ddog-gov.com` | US1-FED |

### User Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /api/datadog/hosts` | List Datadog hosts with filtering |
| `GET /api/datadog/hosts/{id}` | Get host details |
| `GET /api/datadog/summary` | Get summary statistics |
| `POST /api/datadog/hosts/{id}/link` | Link to Muse host |

---

## 🏗️ Architecture

```
                    ┌─────────────────┐
                    │   Web Browser   │
                    └────────┬────────┘
                             │ HTTP :5050
                    ┌────────▼────────┐
                    │   Muse Web App  │
                    │    (Flask)      │
                    └──┬──────────┬───┘
                       │          │
          ┌────────────▼──┐  ┌────▼────────────┐
          │  PostgreSQL   │  │     ClamAV      │
          │   Database    │  │  Virus Scanner  │
          └───────────────┘  └─────────────────┘
                                    │
            ┌───────────────────────┼───────────────────────┐
            │                       │                       │
     ┌──────▼──────┐        ┌──────▼──────┐        ┌──────▼──────┐
     │ Linux Host  │        │ Linux Host  │        │Windows Host │
     │   (SSH)     │        │   (SSH)     │        │  (WinRM)    │
     └─────────────┘        └─────────────┘        └─────────────┘
```

---

## 📚 Documentation

| Document | Description |
|----------|-------------|
| 📦 [Installation](docs/INSTALLATION.md) | Detailed setup instructions |
| ⚙️ [Configuration](docs/CONFIGURATION.md) | Environment variables & options |
| 🔌 [API Reference](docs/API.md) | REST API documentation |
| 🔍 [Scanning Guide](docs/SCANNING.md) | Health & AV scanning details |

---

## 🛠️ Tech Stack

- **Backend:** Python 3.11, Flask, SQLAlchemy
- **Database:** PostgreSQL 15
- **Remote Access:** Paramiko (SSH), PyWinRM
- **Antivirus:** ClamAV with auto-updating definitions
- **Frontend:** Jinja2 templates, vanilla CSS
- **Deployment:** Docker, Docker Compose

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

<p align="center">
  Made with ❤️ for infrastructure security
</p>
