# 🔌 API Reference

Complete REST API documentation for Muse.

---

## 🔐 Authentication

All API endpoints require authentication. Use session-based auth by logging in via the web interface, or include session cookies in your requests.

### Login Flow

```bash
# Get CSRF token and session cookie
curl -c cookies.txt http://localhost:5000/auth/login

# Login (use CSRF token from form)
curl -b cookies.txt -c cookies.txt \
  -X POST http://localhost:5000/auth/login \
  -d "username=admin&password=secret&csrf_token=TOKEN"
```

---

## 📊 Dashboard

### Get Dashboard Statistics

```http
GET /api/dashboard/stats
```

**Response:**
```json
{
  "total_hosts": 5,
  "online_hosts": 3,
  "offline_hosts": 1,
  "error_hosts": 1,
  "pending_hosts": 0
}
```

---

## 🖥️ Hosts

### List All Hosts

```http
GET /api/hosts
```

**Response:**
```json
[
  {
    "id": 1,
    "hostname": "web-server-01",
    "ip_address": "192.168.1.100",
    "os_type": "linux",
    "status": "online",
    "last_scan": "2024-01-15T10:30:00",
    "created_at": "2024-01-01T00:00:00"
  }
]
```

---

### Create Host

```http
POST /api/hosts
Content-Type: application/json
```

**Request Body:**
```json
{
  "hostname": "web-server-01",
  "ip_address": "192.168.1.100",
  "os_type": "linux",
  "ssh_port": 22,
  "username": "admin",
  "password": "secret",
  "ssh_key": "-----BEGIN RSA PRIVATE KEY-----\n..."
}
```

| Field | Type | Required | Description |
|-------|------|:--------:|-------------|
| `hostname` | string | ✅ | Server hostname |
| `ip_address` | string | ❌ | IP address |
| `os_type` | string | ❌ | `linux` or `windows` (default: `linux`) |
| `ssh_port` | integer | ❌ | SSH port (default: `22`) |
| `winrm_port` | integer | ❌ | WinRM port (default: `5985`) |
| `username` | string | ❌ | Auth username |
| `password` | string | ❌ | Auth password |
| `ssh_key` | string | ❌ | SSH private key |

**Response:** `201 Created`
```json
{
  "id": 1,
  "hostname": "web-server-01",
  "ip_address": "192.168.1.100",
  "os_type": "linux",
  "status": "pending",
  "last_scan": null,
  "created_at": "2024-01-15T10:30:00"
}
```

---

### Get Host

```http
GET /api/hosts/{host_id}
```

**Response:**
```json
{
  "id": 1,
  "hostname": "web-server-01",
  "ip_address": "192.168.1.100",
  "os_type": "linux",
  "status": "online",
  "last_scan": "2024-01-15T10:30:00",
  "created_at": "2024-01-01T00:00:00"
}
```

---

### Update Host

```http
PUT /api/hosts/{host_id}
Content-Type: application/json
```

**Request Body:**
```json
{
  "hostname": "web-server-01-updated",
  "ip_address": "192.168.1.101"
}
```

**Response:** `200 OK`

---

### Delete Host

```http
DELETE /api/hosts/{host_id}
```

**Response:** `200 OK`
```json
{
  "message": "Host deleted"
}
```

---

## 🏥 Health Scans

### Trigger Health Scan

```http
POST /api/hosts/{host_id}/scan
Content-Type: application/json
```

**Request Body (optional):**
```json
{
  "password": "override-password"
}
```

**Response:**
```json
{
  "id": 42,
  "host_id": 1,
  "created_at": "2024-01-15T10:30:00",
  "success": true,
  "error_message": null,
  "hostname_reported": "web-server-01",
  "os_info": "Ubuntu 22.04 LTS",
  "uptime": "up 15 days, 3 hours",
  "cpu_usage": 23.5,
  "memory_total": 8589934592,
  "memory_used": 4294967296,
  "memory_percent": 50.0,
  "disk_info": "...",
  "logged_users": "admin    pts/0    2024-01-15 10:00",
  "running_processes": "...",
  "process_count": 142,
  "recent_logs": "...",
  "network_info": "..."
}
```

---

### List Health Scans

```http
GET /api/hosts/{host_id}/scans?limit=20
```

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `limit` | integer | 20 | Max results to return |

**Response:**
```json
[
  {
    "id": 42,
    "host_id": 1,
    "created_at": "2024-01-15T10:30:00",
    "success": true,
    "cpu_usage": 23.5,
    "memory_percent": 50.0,
    "process_count": 142
  }
]
```

---

### Get Health Scan

```http
GET /api/hosts/{host_id}/scans/{scan_id}
```

**Response:** Full scan result object (see Trigger Health Scan response)

---

## 🦠 Antivirus Scans

### Trigger AV Scan

```http
POST /api/hosts/{host_id}/av-scan
Content-Type: application/json
```

**Request Body:**
```json
{
  "scan_type": "quick",
  "paths": ["/custom/path", "/another/path"],
  "password": "override-password"
}
```

| Field | Type | Required | Description |
|-------|------|:--------:|-------------|
| `scan_type` | string | ❌ | `quick`, `full`, or `custom` (default: `quick`) |
| `paths` | array | ❌ | Custom paths (required if `scan_type` is `custom`) |
| `password` | string | ❌ | Override stored password |

**Response:**
```json
{
  "id": 15,
  "host_id": 1,
  "created_at": "2024-01-15T10:30:00",
  "completed_at": "2024-01-15T10:32:15",
  "success": true,
  "error_message": null,
  "scan_type": "quick",
  "paths_scanned": "/tmp,/home,/var/www",
  "files_scanned": 1523,
  "threats_found": 0,
  "threat_details": "No threats detected",
  "scan_summary": "Scanned 1523 files in 3 directories. Found 0 threat(s)."
}
```

---

### List AV Scans

```http
GET /api/hosts/{host_id}/av-scans?limit=20
```

**Response:**
```json
[
  {
    "id": 15,
    "host_id": 1,
    "created_at": "2024-01-15T10:30:00",
    "success": true,
    "scan_type": "quick",
    "files_scanned": 1523,
    "threats_found": 0
  }
]
```

---

### Get AV Scan

```http
GET /api/hosts/{host_id}/av-scans/{scan_id}
```

**Response:** Full AV scan result object (see Trigger AV Scan response)

---

## ❌ Error Responses

All endpoints return errors in this format:

```json
{
  "error": "Error message description"
}
```

### HTTP Status Codes

| Code | Description |
|------|-------------|
| `200` | Success |
| `201` | Created |
| `400` | Bad request (missing/invalid parameters) |
| `401` | Unauthorized (not logged in) |
| `404` | Resource not found |
| `500` | Internal server error |

---

## 🔧 Example: cURL Commands

### Create and Scan a Host

```bash
# Login and save cookies
curl -c cookies.txt -b cookies.txt \
  -X POST http://localhost:5000/auth/login \
  -d "username=admin&password=secret"

# Create host
curl -b cookies.txt \
  -X POST http://localhost:5000/api/hosts \
  -H "Content-Type: application/json" \
  -d '{
    "hostname": "my-server",
    "ip_address": "192.168.1.100",
    "os_type": "linux",
    "username": "root",
    "password": "serverpass"
  }'

# Run health scan
curl -b cookies.txt \
  -X POST http://localhost:5000/api/hosts/1/scan

# Run AV scan
curl -b cookies.txt \
  -X POST http://localhost:5000/api/hosts/1/av-scan \
  -H "Content-Type: application/json" \
  -d '{"scan_type": "full"}'
```

---

## 🐍 Example: Python Client

```python
import requests

# Create session
session = requests.Session()
base_url = "http://localhost:5000"

# Login
session.post(f"{base_url}/auth/login", data={
    "username": "admin",
    "password": "secret"
})

# List hosts
hosts = session.get(f"{base_url}/api/hosts").json()
print(f"Found {len(hosts)} hosts")

# Scan first host
if hosts:
    host_id = hosts[0]["id"]

    # Health scan
    result = session.post(f"{base_url}/api/hosts/{host_id}/scan").json()
    print(f"CPU: {result['cpu_usage']}%")

    # AV scan
    av_result = session.post(
        f"{base_url}/api/hosts/{host_id}/av-scan",
        json={"scan_type": "quick"}
    ).json()
    print(f"Threats found: {av_result['threats_found']}")
```

---

[← Back to README](../README.md)
