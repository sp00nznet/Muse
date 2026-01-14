# ⚙️ Configuration Guide

Complete reference for all Muse configuration options.

---

## 🌍 Environment Variables

### Application Settings

| Variable | Description | Default | Required |
|----------|-------------|---------|:--------:|
| `SECRET_KEY` | Flask session encryption key | `dev-secret-key...` | ✅ |
| `DATABASE_URL` | PostgreSQL connection string | `postgresql://muse:muse@db:5432/muse` | ✅ |
| `CLAMAV_HOST` | ClamAV daemon hostname | `clamav` | ❌ |
| `CLAMAV_PORT` | ClamAV daemon port | `3310` | ❌ |

### Example `.env` File

```env
# Application
SECRET_KEY=a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6

# Database
DATABASE_URL=postgresql://muse:supersecretpassword@db:5432/muse

# ClamAV
CLAMAV_HOST=clamav
CLAMAV_PORT=3310
```

---

## 🐳 Docker Compose Configuration

### Service: `web`

```yaml
web:
  build: .
  ports:
    - "5050:5050"           # Change left number for different host port
  environment:
    - SECRET_KEY=${SECRET_KEY}
    - DATABASE_URL=postgresql://muse:muse@db:5432/muse
    - CLAMAV_HOST=clamav
    - CLAMAV_PORT=3310
  depends_on:
    db:
      condition: service_healthy
    clamav:
      condition: service_healthy
  restart: unless-stopped
```

### Service: `db` (PostgreSQL)

```yaml
db:
  image: postgres:15-alpine
  environment:
    - POSTGRES_USER=muse       # Database username
    - POSTGRES_PASSWORD=muse   # ⚠️ Change in production!
    - POSTGRES_DB=muse         # Database name
  volumes:
    - postgres_data:/var/lib/postgresql/data
```

### Service: `clamav`

```yaml
clamav:
  image: clamav/clamav:latest
  volumes:
    - clamav_data:/var/lib/clamav    # Virus definitions
    - scan_files:/scandir             # Temp scan directory
  environment:
    - CLAMAV_NO_FRESHCLAMD=false     # Enable auto-updates
```

---

## 🖥️ Host Configuration

### Adding Linux Hosts (SSH)

| Field | Description | Example |
|-------|-------------|---------|
| Hostname | Server name or FQDN | `web-server-01` |
| IP Address | IPv4/IPv6 address | `192.168.1.100` |
| SSH Port | SSH service port | `22` |
| Username | SSH username | `admin` |
| Password | SSH password | `********` |
| SSH Key | Private key (optional) | `-----BEGIN RSA...` |

**SSH Key Authentication:**
```
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA...
...
-----END RSA PRIVATE KEY-----
```

### Adding Windows Hosts (WinRM)

| Field | Description | Example |
|-------|-------------|---------|
| Hostname | Server name or FQDN | `win-server-01` |
| IP Address | IPv4/IPv6 address | `192.168.1.200` |
| WinRM Port | WinRM HTTP port | `5985` |
| Username | Windows username | `Administrator` |
| Password | Windows password | `********` |

**Enable WinRM on Windows:**
```powershell
# Run as Administrator
winrm quickconfig -y
winrm set winrm/config/service '@{AllowUnencrypted="true"}'
winrm set winrm/config/service/auth '@{Basic="true"}'
```

> ⚠️ For production, configure WinRM with HTTPS (port 5986)

---

## 🔐 Authentication Settings

### User Roles

| Role | Permissions |
|------|-------------|
| **Admin** | Full access, user management |
| **User** | Manage own hosts only |

> 💡 The first registered user automatically becomes an admin.

### Password Requirements

- Minimum 8 characters
- Stored using bcrypt hashing

---

## 🦠 ClamAV Configuration

### Virus Definition Updates

ClamAV automatically updates virus definitions via `freshclam`:

- **Update frequency:** Every 2 hours (default)
- **Storage location:** `/var/lib/clamav` (Docker volume)

### Scan Limits

| Setting | Value | Description |
|---------|-------|-------------|
| Max file size | 10 MB | Files larger are skipped |
| Max files per dir | 500 | Prevents runaway scans |
| Scan timeout | 60s | Per-directory timeout |

### Custom ClamAV Settings

Mount a custom `clamd.conf`:

```yaml
clamav:
  image: clamav/clamav:latest
  volumes:
    - ./clamd.conf:/etc/clamav/clamd.conf:ro
```

---

## 🌐 Network Configuration

### Required Ports

| Service | Port | Direction | Purpose |
|---------|------|-----------|---------|
| Muse Web | 5050 | Inbound | Web interface |
| PostgreSQL | 5432 | Internal | Database |
| ClamAV | 3310 | Internal | Virus scanning |

### Outbound Connections

| Destination | Port | Purpose |
|-------------|------|---------|
| Target hosts | 22 | SSH scanning |
| Target hosts | 5985 | WinRM scanning |
| database.clamav.net | 443 | Virus definition updates |

### Firewall Rules (iptables)

```bash
# Allow web access
iptables -A INPUT -p tcp --dport 5050 -j ACCEPT

# Allow outbound SSH
iptables -A OUTPUT -p tcp --dport 22 -j ACCEPT

# Allow outbound WinRM
iptables -A OUTPUT -p tcp --dport 5985 -j ACCEPT
```

---

## 📊 Performance Tuning

### Gunicorn Workers

```yaml
# docker-compose.yml
web:
  command: gunicorn --bind 0.0.0.0:5050 --workers 4 --threads 2 run:app
```

| Setting | Recommendation |
|---------|----------------|
| Workers | `(2 × CPU cores) + 1` |
| Threads | `2-4` per worker |

### PostgreSQL

```yaml
db:
  command: postgres -c 'max_connections=100' -c 'shared_buffers=256MB'
```

### Memory Allocation

| Service | Minimum | Recommended |
|---------|---------|-------------|
| Web | 256 MB | 512 MB |
| PostgreSQL | 256 MB | 512 MB |
| ClamAV | 1 GB | 2 GB |

---

## 🔄 Backup Configuration

### Database Backup

```bash
# Create backup
docker-compose exec db pg_dump -U muse muse > backup.sql

# Restore backup
docker-compose exec -T db psql -U muse muse < backup.sql
```

### Automated Backups (cron)

```bash
# Add to crontab
0 2 * * * cd /path/to/muse && docker-compose exec -T db pg_dump -U muse muse | gzip > backups/muse_$(date +\%Y\%m\%d).sql.gz
```

---

[← Back to README](../README.md)
