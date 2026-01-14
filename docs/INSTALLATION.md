# 📦 Installation Guide

This guide covers all methods of installing and deploying Muse.

---

## 🐳 Docker Installation (Recommended)

### Prerequisites

- Docker Engine 20.10+
- Docker Compose 2.0+
- 2GB RAM minimum (4GB recommended for ClamAV)
- 10GB disk space

### Step 1: Clone the Repository

```bash
git clone https://github.com/yourusername/muse.git
cd muse
```

### Step 2: Configure Environment

```bash
# Copy the example environment file
cp .env.example .env

# Edit with your settings
nano .env
```

**Required settings:**
```env
SECRET_KEY=your-super-secret-key-here
```

> 💡 Generate a secure key: `python -c "import secrets; print(secrets.token_hex(32))"`

### Step 3: Launch Services

```bash
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f
```

### Step 4: Verify Installation

```bash
# Check service status
docker-compose ps

# Expected output:
# NAME                STATUS              PORTS
# muse-web-1          running             0.0.0.0:5050->5050/tcp
# muse-db-1           running (healthy)   5432/tcp
# muse-clamav-1       running (healthy)   3310/tcp
```

🎉 **Done!** Visit http://localhost:5050

---

## 🖥️ Manual Installation

For development or non-Docker deployments.

### Prerequisites

- Python 3.11+
- PostgreSQL 15+
- ClamAV daemon (clamd)

### Step 1: Set Up Python Environment

```bash
# Clone repository
git clone https://github.com/yourusername/muse.git
cd muse

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/macOS
# or
.\venv\Scripts\activate   # Windows

# Install dependencies
pip install -r requirements.txt
```

### Step 2: Set Up PostgreSQL

```bash
# Create database and user
sudo -u postgres psql

CREATE USER muse WITH PASSWORD 'your-password';
CREATE DATABASE muse OWNER muse;
\q
```

### Step 3: Set Up ClamAV

**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install clamav clamav-daemon
sudo freshclam
sudo systemctl enable clamav-daemon
sudo systemctl start clamav-daemon
```

**CentOS/RHEL:**
```bash
sudo yum install epel-release
sudo yum install clamav clamav-server clamav-update
sudo freshclam
sudo systemctl enable clamd@scan
sudo systemctl start clamd@scan
```

### Step 4: Configure Environment

```bash
export SECRET_KEY="your-secret-key"
export DATABASE_URL="postgresql://muse:your-password@localhost:5432/muse"
export CLAMAV_HOST="localhost"
export CLAMAV_PORT="3310"
```

### Step 5: Run Application

```bash
# Development
python run.py

# Production
gunicorn --bind 0.0.0.0:5050 --workers 4 run:app
```

---

## ☁️ Cloud Deployment

### AWS EC2

1. Launch an EC2 instance (t3.medium or larger)
2. Install Docker and Docker Compose
3. Clone repo and run `docker-compose up -d`
4. Configure Security Group to allow port 5050

### DigitalOcean

```bash
# Using doctl
doctl compute droplet create muse \
  --image docker-20-04 \
  --size s-2vcpu-4gb \
  --region nyc1
```

### Docker Swarm

```bash
docker stack deploy -c docker-compose.yml muse
```

---

## 🔒 Production Checklist

Before going to production, ensure:

- [ ] ✅ Changed `SECRET_KEY` to a secure random value
- [ ] ✅ Set up HTTPS with a reverse proxy (nginx/traefik)
- [ ] ✅ Changed default PostgreSQL password
- [ ] ✅ Configured firewall rules
- [ ] ✅ Set up log rotation
- [ ] ✅ Configured backup for PostgreSQL data
- [ ] ✅ Reviewed and restricted network access

### Example Nginx Configuration

```nginx
server {
    listen 80;
    server_name muse.yourdomain.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl;
    server_name muse.yourdomain.com;

    ssl_certificate /etc/letsencrypt/live/muse.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/muse.yourdomain.com/privkey.pem;

    location / {
        proxy_pass http://localhost:5050;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

---

## 🔄 Updating

### Docker

```bash
cd muse
git pull origin main
docker-compose down
docker-compose build --no-cache
docker-compose up -d
```

### Manual

```bash
cd muse
git pull origin main
source venv/bin/activate
pip install -r requirements.txt
# Restart your application server
```

---

## 🐛 Troubleshooting

### ClamAV Won't Start

```bash
# Check ClamAV logs
docker-compose logs clamav

# Common issue: virus definitions not downloaded
# Wait 2-3 minutes for freshclam to complete
```

### Database Connection Failed

```bash
# Check PostgreSQL is running
docker-compose ps db

# Check connection
docker-compose exec db psql -U muse -d muse -c "SELECT 1"
```

### Port Already in Use

```bash
# Find process using port 5050
lsof -i :5050

# Change port in docker-compose.yml
ports:
  - "8080:5050"  # Use port 8080 instead
```

---

[← Back to README](../README.md)
