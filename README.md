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
| 🐧 **Linux Support** | Connect via SSH with password or key authentication |
| 🪟 **Windows Support** | Connect via WinRM for Windows servers |
| 🔐 **User Authentication** | Secure login with session management |
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

🌐 Open **http://localhost:5000** and create your first account!

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

### 🦠 Antivirus Scan

| Scan Type | Description |
|-----------|-------------|
| **Quick** | Common malware locations (`/tmp`, `/home`, `C:\Users`) |
| **Full** | Comprehensive scan including application directories |
| **Custom** | User-defined paths |

---

## 🏗️ Architecture

```
                    ┌─────────────────┐
                    │   Web Browser   │
                    └────────┬────────┘
                             │ HTTP :5000
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
