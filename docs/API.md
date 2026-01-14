# 🔌 API Reference

Complete REST API documentation for Muse.

---

## 🔐 Authentication

All API endpoints require authentication. Use session-based auth by logging in via the web interface, or include session cookies in your requests.

### Login Flow

```bash
# Get CSRF token and session cookie
curl -c cookies.txt http://localhost:5050/auth/login

# Login (use CSRF token from form)
curl -b cookies.txt -c cookies.txt \
  -X POST http://localhost:5050/auth/login \
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

## 👤 User Management

### Get Current User Profile

```http
GET /api/users/me
```

**Response:**
```json
{
  "id": 1,
  "username": "admin",
  "email": "admin@example.com",
  "is_admin": true,
  "created_at": "2024-01-01T00:00:00",
  "host_count": 5
}
```

---

### Update Current User Profile

```http
PUT /api/users/me
Content-Type: application/json
```

**Request Body:**
```json
{
  "username": "new_username",
  "email": "new_email@example.com"
}
```

**Response:** `200 OK` with updated user object

---

### Change Password

```http
PUT /api/users/me/password
Content-Type: application/json
```

**Request Body:**
```json
{
  "current_password": "old_password",
  "new_password": "new_secure_password"
}
```

**Response:** `200 OK`
```json
{
  "message": "Password changed successfully"
}
```

---

### List All Users (Admin Only)

```http
GET /api/users
```

**Response:**
```json
[
  {
    "id": 1,
    "username": "admin",
    "email": "admin@example.com",
    "is_admin": true,
    "created_at": "2024-01-01T00:00:00",
    "host_count": 5
  }
]
```

---

### Get User (Admin Only)

```http
GET /api/users/{user_id}
```

**Response:** Single user object

---

### Delete User (Admin Only)

```http
DELETE /api/users/{user_id}
```

**Response:** `200 OK`
```json
{
  "message": "User deleted successfully"
}
```

---

## 🔄 Bulk Operations

### Bulk Health Scan

Trigger health scans for multiple hosts at once.

```http
POST /api/hosts/bulk-scan
Content-Type: application/json
```

**Request Body:**
```json
{
  "host_ids": [1, 2, 3],
  "password": "optional_override_password"
}
```

**Response:**
```json
{
  "total": 3,
  "successful": 2,
  "failed": 1,
  "results": [
    {
      "host_id": 1,
      "success": true,
      "scan_id": 42,
      "error": null
    },
    {
      "host_id": 2,
      "success": true,
      "scan_id": 43,
      "error": null
    },
    {
      "host_id": 3,
      "success": false,
      "error": "Connection timeout"
    }
  ]
}
```

---

### Bulk AV Scan

Trigger AV scans for multiple hosts at once.

```http
POST /api/hosts/bulk-av-scan
Content-Type: application/json
```

**Request Body:**
```json
{
  "host_ids": [1, 2, 3],
  "scan_type": "quick",
  "password": "optional_override_password"
}
```

**Response:**
```json
{
  "total": 3,
  "successful": 2,
  "failed": 1,
  "total_threats": 1,
  "results": [
    {
      "host_id": 1,
      "success": true,
      "scan_id": 15,
      "threats_found": 0,
      "error": null
    },
    {
      "host_id": 2,
      "success": true,
      "scan_id": 16,
      "threats_found": 1,
      "error": null
    },
    {
      "host_id": 3,
      "success": false,
      "error": "Connection timeout"
    }
  ]
}
```

---

## 📈 Advanced Dashboard & Analytics

### Dashboard Overview

Get comprehensive dashboard overview with recent activity.

```http
GET /api/dashboard/overview
```

**Response:**
```json
{
  "host_stats": {
    "total": 5,
    "online": 3,
    "offline": 1,
    "error": 1,
    "pending": 0
  },
  "scan_activity": {
    "health_scans_24h": 12,
    "av_scans_24h": 5
  },
  "threat_stats": {
    "total_threats_found": 3,
    "threats_last_24h": 1
  },
  "recent_scans": [
    {
      "id": 42,
      "host_id": 1,
      "success": true,
      "cpu_usage": 23.5,
      "memory_percent": 50.0,
      "created_at": "2024-01-15T10:30:00"
    }
  ],
  "hosts_with_issues": [
    {
      "host_id": 2,
      "hostname": "db-server",
      "issues": ["High CPU: 92.5%"]
    }
  ]
}
```

---

### Host Metrics History

Get historical metrics for graphing.

```http
GET /api/hosts/{host_id}/metrics/history?hours=24&limit=100
```

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `hours` | integer | 24 | Time range in hours |
| `limit` | integer | 100 | Max data points |

**Response:**
```json
{
  "host_id": 1,
  "hostname": "web-server-01",
  "period_hours": 24,
  "data_points": 48,
  "metrics": [
    {
      "timestamp": "2024-01-15T00:00:00",
      "cpu_usage": 23.5,
      "memory_percent": 50.0,
      "memory_used": 4294967296,
      "memory_total": 8589934592,
      "process_count": 142
    }
  ]
}
```

---

### Host Health Score

Calculate a health score (0-100) for a host.

```http
GET /api/hosts/{host_id}/health-score
```

**Response:**
```json
{
  "host_id": 1,
  "hostname": "web-server-01",
  "health_score": 85,
  "status": "healthy",
  "factors": [
    {
      "factor": "memory",
      "impact": -10,
      "value": 75.5
    },
    {
      "factor": "threats",
      "impact": -5,
      "value": 1
    }
  ],
  "last_scan": "2024-01-15T10:30:00"
}
```

**Health Status:**

| Score | Status |
|-------|--------|
| 80-100 | `healthy` |
| 60-79 | `warning` |
| 0-59 | `critical` |

---

## 🛡️ Threat Analytics

### Threats Summary

Get a summary of all threats across your hosts.

```http
GET /api/threats/summary
```

**Response:**
```json
{
  "total_threats": 5,
  "hosts_affected": 2,
  "total_hosts": 5,
  "by_host": [
    {
      "host_id": 2,
      "hostname": "web-server",
      "total_threats": 3,
      "scan_count": 2,
      "latest_scan": "2024-01-15T10:30:00"
    }
  ]
}
```

---

### Recent Threats

Get recent threat detections.

```http
GET /api/threats/recent?days=7&limit=20
```

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `days` | integer | 7 | Days to look back |
| `limit` | integer | 20 | Max results |

**Response:**
```json
{
  "period_days": 7,
  "total_results": 2,
  "threats": [
    {
      "scan_id": 15,
      "host_id": 2,
      "hostname": "web-server",
      "scan_type": "full",
      "threats_found": 2,
      "threat_details": "Eicar-Test-Signature FOUND",
      "created_at": "2024-01-15T10:30:00"
    }
  ]
}
```

---

## 🔍 Search & Filtering

### Search Hosts

Search hosts with filters and pagination.

```http
GET /api/hosts/search?hostname=web&status=online&os_type=linux&sort_by=hostname&sort_order=asc&page=1&per_page=20
```

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `hostname` | string | - | Partial hostname match |
| `status` | string | - | Filter by status (`online`, `offline`, `error`, `pending`) |
| `os_type` | string | - | Filter by OS (`linux`, `windows`) |
| `ip` | string | - | Partial IP match |
| `sort_by` | string | `hostname` | Sort field (`hostname`, `status`, `last_scan`, `created_at`) |
| `sort_order` | string | `asc` | Sort direction (`asc`, `desc`) |
| `page` | integer | 1 | Page number |
| `per_page` | integer | 20 | Results per page |

**Response:**
```json
{
  "hosts": [
    {
      "id": 1,
      "hostname": "web-server-01",
      "ip_address": "192.168.1.100",
      "os_type": "linux",
      "status": "online"
    }
  ],
  "pagination": {
    "page": 1,
    "per_page": 20,
    "total_pages": 3,
    "total_items": 45
  }
}
```

---

### Search Scans

Search scan results with filters.

```http
GET /api/scans/search?host_id=1&success=true&start_date=2024-01-01&min_cpu=80&page=1&per_page=20
```

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `host_id` | integer | - | Filter by host |
| `success` | boolean | - | Filter by success (`true`, `false`) |
| `start_date` | ISO date | - | Filter scans after this date |
| `end_date` | ISO date | - | Filter scans before this date |
| `min_cpu` | float | - | Filter by minimum CPU usage |
| `min_memory` | float | - | Filter by minimum memory usage |
| `page` | integer | 1 | Page number |
| `per_page` | integer | 20 | Results per page |

**Response:**
```json
{
  "scans": [
    {
      "id": 42,
      "host_id": 1,
      "success": true,
      "cpu_usage": 92.5,
      "memory_percent": 65.0,
      "created_at": "2024-01-15T10:30:00"
    }
  ],
  "pagination": {
    "page": 1,
    "per_page": 20,
    "total_pages": 5,
    "total_items": 98
  }
}
```

---

## 📤 Export

### Export Hosts

Export all hosts data as JSON.

```http
GET /api/export/hosts?include_latest_scan=true&include_latest_av_scan=true
```

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `include_latest_scan` | boolean | `false` | Include latest health scan |
| `include_latest_av_scan` | boolean | `false` | Include latest AV scan |

**Response:**
```json
{
  "exported_at": "2024-01-15T12:00:00",
  "user": "admin",
  "total_hosts": 5,
  "hosts": [
    {
      "id": 1,
      "hostname": "web-server-01",
      "latest_scan": { ... },
      "latest_av_scan": { ... }
    }
  ]
}
```

---

### Export Health Scans

Export health scan results as JSON.

```http
GET /api/export/scans?days=30
```

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `days` | integer | 30 | Export scans from last N days |

**Response:**
```json
{
  "exported_at": "2024-01-15T12:00:00",
  "user": "admin",
  "period_days": 30,
  "total_scans": 150,
  "scans": [
    {
      "id": 42,
      "host_id": 1,
      "hostname": "web-server-01",
      "success": true,
      "cpu_usage": 23.5,
      "created_at": "2024-01-15T10:30:00"
    }
  ]
}
```

---

### Export AV Scans

Export AV scan results as JSON.

```http
GET /api/export/av-scans?days=30&threats_only=true
```

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `days` | integer | 30 | Export scans from last N days |
| `threats_only` | boolean | `false` | Only export scans with threats |

**Response:**
```json
{
  "exported_at": "2024-01-15T12:00:00",
  "user": "admin",
  "period_days": 30,
  "threats_only": true,
  "total_scans": 3,
  "total_threats": 5,
  "scans": [
    {
      "id": 15,
      "host_id": 2,
      "hostname": "web-server",
      "threats_found": 2,
      "threat_details": "...",
      "created_at": "2024-01-15T10:30:00"
    }
  ]
}
```

---

## 🔄 Server Comparison

### Compare Hosts Side-by-Side

Compare two or more hosts with full system details and automatic difference detection.

```http
POST /api/compare/hosts
Content-Type: application/json
```

**Request Body:**
```json
{
  "host_ids": [1, 2, 3]
}
```

**Response:**
```json
{
  "compared_at": "2024-01-15T12:00:00",
  "host_count": 3,
  "hosts": [
    {
      "host_id": 1,
      "hostname": "web-server-01",
      "os_type": "linux",
      "status": "online",
      "last_scan": "2024-01-15T10:30:00",
      "snapshot": {
        "os_pretty_name": "Ubuntu 22.04.3 LTS",
        "kernel_version": "5.15.0-91-generic",
        "cpu_usage": 23.5,
        "memory_percent": 45.2,
        "pending_update_count": 5
      },
      "metrics": { ... },
      "system": { ... },
      "updates": { ... },
      "drivers": { ... }
    }
  ],
  "differences": {
    "os_version_mismatch": true,
    "kernel_mismatch": true,
    "update_status_varies": false,
    "details": [
      {"type": "kernel_version", "message": "Kernel versions differ: 5.15.0-91, 5.15.0-89"}
    ]
  }
}
```

---

### Compare Event Logs

Compare event logs between hosts to identify common issues.

```http
POST /api/compare/events
Content-Type: application/json
```

**Request Body:**
```json
{
  "host_ids": [1, 2],
  "event_type": "all"
}
```

**Event Types:** `all`, `security`, `system`, `application`, `critical`

**Response:**
```json
{
  "compared_at": "2024-01-15T12:00:00",
  "event_type": "all",
  "host_count": 2,
  "hosts": [
    {
      "host_id": 1,
      "hostname": "web-server-01",
      "events": {
        "security": "...",
        "system": "...",
        "application": "...",
        "critical": "...",
        "summary": "Critical events (24h): 0\nError events (24h): 2"
      }
    }
  ]
}
```

---

### Compare Update Status

Compare pending updates and patch levels between hosts.

```http
POST /api/compare/updates
Content-Type: application/json
```

**Request Body:**
```json
{
  "host_ids": [1, 2, 3]
}
```

**Response:**
```json
{
  "compared_at": "2024-01-15T12:00:00",
  "host_count": 3,
  "hosts_needing_updates": 2,
  "hosts": [
    {
      "host_id": 1,
      "hostname": "web-server-01",
      "os_type": "linux",
      "updates": {
        "pending_count": 12,
        "pending_updates": "...",
        "update_history": "...",
        "kernel_version": "5.15.0-91-generic"
      }
    }
  ]
}
```

---

### Compare Driver Information

Compare installed drivers and available updates between hosts.

```http
POST /api/compare/drivers
Content-Type: application/json
```

**Request Body:**
```json
{
  "host_ids": [1, 2]
}
```

**Response:**
```json
{
  "compared_at": "2024-01-15T12:00:00",
  "host_count": 2,
  "hosts": [
    {
      "host_id": 1,
      "hostname": "web-server-01",
      "os_type": "windows",
      "drivers": {
        "driver_info": "[{\"DeviceName\": \"Intel UHD\", \"DriverVersion\": \"31.0.101.4502\"}]",
        "driver_updates": "{\"AvailableDriverUpdates\": 2}"
      }
    }
  ]
}
```

---

## 📋 At-a-Glance Summaries

### Get Host Summary

Get a quick at-a-glance summary for a single host.

```http
GET /api/hosts/{host_id}/summary
```

**Response:**
```json
{
  "host_id": 1,
  "hostname": "web-server-01",
  "status": "online",
  "os_type": "linux",
  "has_scan_data": true,
  "last_scan": "2024-01-15T10:30:00",
  "at_a_glance": {
    "os_name": "Ubuntu 22.04.3 LTS",
    "os_version": "22.04",
    "kernel_version": "5.15.0-91-generic",
    "build_number": "",
    "uptime": "up 15 days, 3 hours",
    "cpu_usage": 23.5,
    "memory_percent": 45.2,
    "memory_total_gb": 16.0,
    "process_count": 142,
    "pending_updates": 5,
    "recent_threats": 0,
    "manufacturer": "Dell Inc.",
    "model": "PowerEdge R640"
  },
  "health_warnings": ["High CPU: 85.2%"],
  "health_status": "warning"
}
```

---

### Get All Hosts Summary

Get at-a-glance summaries for all your hosts.

```http
GET /api/summary/all
```

**Response:**
```json
{
  "generated_at": "2024-01-15T12:00:00",
  "total_hosts": 10,
  "by_status": {
    "online": 7,
    "offline": 1,
    "error": 1,
    "pending": 1
  },
  "hosts": [
    {
      "host_id": 1,
      "hostname": "web-server-01",
      "status": "online",
      "os_type": "linux",
      "last_scan": "2024-01-15T10:30:00",
      "os_name": "Ubuntu 22.04.3 LTS",
      "kernel_version": "5.15.0-91-generic",
      "cpu_usage": 23.5,
      "memory_percent": 45.2,
      "pending_updates": 5
    }
  ]
}
```

---

### Get Update Summary

Get a summary of update status across all hosts.

```http
GET /api/summary/updates
```

**Response:**
```json
{
  "hosts_scanned": 10,
  "hosts_up_to_date": 6,
  "hosts_need_updates": 4,
  "total_pending_updates": 47,
  "by_host": [
    {
      "host_id": 3,
      "hostname": "db-server",
      "os_type": "linux",
      "pending_count": 23,
      "kernel_version": "5.15.0-89-generic",
      "last_update_check": "2024-01-14T08:00:00",
      "last_scan": "2024-01-15T10:30:00"
    }
  ]
}
```

---

### Get Version Summary

Get a summary of OS and kernel versions across all hosts, grouped by version.

```http
GET /api/summary/versions
```

**Response:**
```json
{
  "generated_at": "2024-01-15T12:00:00",
  "linux_versions": [
    {
      "kernel_version": "5.15.0-91-generic",
      "os_name": "Ubuntu 22.04.3 LTS",
      "hosts": [
        {"host_id": 1, "hostname": "web-01", "os_version": "22.04"},
        {"host_id": 2, "hostname": "web-02", "os_version": "22.04"}
      ]
    }
  ],
  "windows_versions": [
    {
      "kernel_version": "10.0.19045.0",
      "os_name": "Microsoft Windows Server 2022",
      "hosts": [
        {"host_id": 5, "hostname": "dc-01", "build_number": "20348.2159"}
      ]
    }
  ],
  "linux_host_count": 6,
  "windows_host_count": 4
}
```

---

## 🔐 Admin Panel - Service Accounts (Admin Only)

Service accounts allow centralized credential management for connecting to hosts.

### List Service Accounts

```http
GET /api/admin/service-accounts
```

**Response:**
```json
[
  {
    "id": 1,
    "name": "Linux Production",
    "description": "Service account for production Linux servers",
    "account_type": "linux_key",
    "is_default": true,
    "is_active": true,
    "domain": null,
    "username": "svc_muse",
    "has_password": false,
    "has_ssh_key": true,
    "created_at": "2024-01-15T10:00:00",
    "host_count": 15
  },
  {
    "id": 2,
    "name": "Windows Domain",
    "description": "Domain service account for Windows servers",
    "account_type": "windows_domain",
    "is_default": true,
    "is_active": true,
    "domain": "CONTOSO.COM",
    "username": "svc_muse",
    "has_password": true,
    "has_ssh_key": false,
    "created_at": "2024-01-15T10:00:00",
    "host_count": 10
  }
]
```

---

### Create Service Account

```http
POST /api/admin/service-accounts
Content-Type: application/json
```

**Request Body (Windows Domain):**
```json
{
  "name": "Windows Production",
  "description": "Domain account for Windows servers",
  "account_type": "windows_domain",
  "domain": "CONTOSO.COM",
  "username": "svc_muse",
  "password": "SecurePassword123!",
  "is_default": true,
  "is_active": true
}
```

**Request Body (Linux Password):**
```json
{
  "name": "Linux Production",
  "account_type": "linux_password",
  "username": "svc_muse",
  "password": "SecurePassword123!",
  "is_default": false
}
```

**Request Body (Linux SSH Key):**
```json
{
  "name": "Linux SSH Key",
  "account_type": "linux_key",
  "username": "svc_muse",
  "ssh_key": "-----BEGIN RSA PRIVATE KEY-----\n...\n-----END RSA PRIVATE KEY-----",
  "ssh_key_passphrase": "optional_passphrase",
  "is_default": true
}
```

**Account Types:**
- `windows_domain` - Windows domain credentials (requires domain, username, password)
- `linux_password` - Linux username/password (requires username, password)
- `linux_key` - Linux SSH key authentication (requires username, ssh_key)

**Response:** `201 Created` with service account object

---

### Update Service Account

```http
PUT /api/admin/service-accounts/{id}
Content-Type: application/json
```

**Request Body:**
```json
{
  "name": "Updated Name",
  "description": "Updated description",
  "is_active": true,
  "password": "NewPassword123!"
}
```

**Response:** `200 OK` with updated service account object

---

### Delete Service Account

```http
DELETE /api/admin/service-accounts/{id}
```

**Response:** `200 OK`
```json
{
  "message": "Service account deleted successfully"
}
```

> ⚠️ Cannot delete if hosts are assigned to this service account.

---

### Test Service Account

```http
POST /api/admin/service-accounts/{id}/test
Content-Type: application/json
```

**Request Body:**
```json
{
  "test_host": "192.168.1.100"
}
```

**Response:**
```json
{
  "account_id": 1,
  "account_name": "Linux Production",
  "account_type": "linux_key",
  "test_time": "2024-01-15T12:00:00",
  "success": true,
  "message": "Successfully connected to 192.168.1.100",
  "hostname": "web-server-01"
}
```

---

## 🏢 Admin Panel - Domain Controllers (Admin Only)

Configure Active Directory/LDAP domain controllers for user authentication.

### List Domain Controllers

```http
GET /api/admin/domain-controllers
```

**Response:**
```json
[
  {
    "id": 1,
    "name": "Primary DC",
    "description": "Main domain controller",
    "server_address": "dc01.contoso.com",
    "port": 389,
    "use_ssl": false,
    "use_start_tls": true,
    "domain_name": "contoso.com",
    "base_dn": "DC=contoso,DC=com",
    "user_search_base": "OU=Users,DC=contoso,DC=com",
    "user_search_filter": "(sAMAccountName={username})",
    "bind_username": "svc_muse@contoso.com",
    "admin_group_dn": "CN=Muse Admins,OU=Groups,DC=contoso,DC=com",
    "user_group_dn": "CN=Muse Users,OU=Groups,DC=contoso,DC=com",
    "is_active": true,
    "is_primary": true,
    "priority": 100,
    "last_connection_test": "2024-01-15T11:00:00",
    "last_connection_status": "success",
    "created_at": "2024-01-15T10:00:00"
  }
]
```

---

### Create Domain Controller

```http
POST /api/admin/domain-controllers
Content-Type: application/json
```

**Request Body:**
```json
{
  "name": "Primary DC",
  "description": "Main domain controller",
  "server_address": "dc01.contoso.com",
  "port": 389,
  "use_ssl": false,
  "use_start_tls": true,
  "domain_name": "contoso.com",
  "base_dn": "DC=contoso,DC=com",
  "user_search_base": "OU=Users,DC=contoso,DC=com",
  "user_search_filter": "(sAMAccountName={username})",
  "bind_username": "svc_muse@contoso.com",
  "bind_password": "ServiceAccountPassword!",
  "admin_group_dn": "CN=Muse Admins,OU=Groups,DC=contoso,DC=com",
  "user_group_dn": "CN=Muse Users,OU=Groups,DC=contoso,DC=com",
  "is_active": true,
  "is_primary": true,
  "priority": 100
}
```

**Response:** `201 Created` with domain controller object

---

### Update Domain Controller

```http
PUT /api/admin/domain-controllers/{id}
Content-Type: application/json
```

**Request Body:**
```json
{
  "server_address": "dc02.contoso.com",
  "is_primary": true,
  "bind_password": "NewServicePassword!"
}
```

**Response:** `200 OK` with updated domain controller object

---

### Rename Domain Controller

```http
PUT /api/admin/domain-controllers/{id}/rename
Content-Type: application/json
```

**Request Body:**
```json
{
  "name": "Backup DC"
}
```

**Response:**
```json
{
  "message": "Domain controller renamed successfully",
  "old_name": "Primary DC",
  "new_name": "Backup DC"
}
```

---

### Delete Domain Controller

```http
DELETE /api/admin/domain-controllers/{id}
```

**Response:** `200 OK`
```json
{
  "message": "Domain controller deleted successfully"
}
```

> ⚠️ Cannot delete if users are authenticated via this domain controller.

---

### Test Domain Controller Connection

```http
POST /api/admin/domain-controllers/{id}/test
Content-Type: application/json
```

**Request Body (Optional - test user authentication):**
```json
{
  "test_username": "john.doe",
  "test_password": "UserPassword123!"
}
```

**Response:**
```json
{
  "dc_id": 1,
  "dc_name": "Primary DC",
  "server_address": "dc01.contoso.com",
  "test_time": "2024-01-15T12:00:00",
  "connection_test": {
    "success": true,
    "message": "Successfully reached dc01.contoso.com:389"
  },
  "bind_test": {
    "success": true,
    "message": "Successfully bound as svc_muse@contoso.com"
  },
  "user_test": {
    "success": true,
    "message": "User john.doe authenticated successfully",
    "user_dn": "CN=John Doe,OU=Users,DC=contoso,DC=com",
    "is_admin": false
  },
  "server_info": {
    "vendor": "Microsoft",
    "supported_controls": 42
  }
}
```

---

## ⚙️ Admin Panel - Authentication Settings (Admin Only)

Configure global authentication settings.

### Get Authentication Settings

```http
GET /api/admin/auth-settings
```

**Response:**
```json
{
  "id": 1,
  "allow_local_auth": true,
  "allow_domain_auth": true,
  "require_domain_auth": false,
  "auto_create_domain_users": true,
  "default_domain_user_admin": false,
  "session_timeout_minutes": 480,
  "updated_at": "2024-01-15T10:00:00",
  "active_domain_controllers": 2
}
```

---

### Update Authentication Settings

```http
PUT /api/admin/auth-settings
Content-Type: application/json
```

**Request Body:**
```json
{
  "allow_local_auth": true,
  "allow_domain_auth": true,
  "require_domain_auth": false,
  "auto_create_domain_users": true,
  "default_domain_user_admin": false,
  "session_timeout_minutes": 480
}
```

**Response:** `200 OK` with updated settings

---

## 🔗 Admin Panel - Host Service Account Assignment (Admin Only)

### Assign Service Account to Host

```http
PUT /api/admin/hosts/{host_id}/service-account
Content-Type: application/json
```

**Request Body:**
```json
{
  "service_account_id": 1,
  "use_service_account": true
}
```

**To remove assignment:**
```json
{
  "service_account_id": null
}
```

**Response:**
```json
{
  "host_id": 1,
  "hostname": "web-server-01",
  "service_account_id": 1,
  "use_service_account": true
}
```

---

### Bulk Assign Service Account

```http
POST /api/admin/hosts/bulk-assign-service-account
Content-Type: application/json
```

**Request Body:**
```json
{
  "host_ids": [1, 2, 3, 4, 5],
  "service_account_id": 1
}
```

**Response:**
```json
{
  "total": 5,
  "successful": 4,
  "failed": 1,
  "results": [
    {"host_id": 1, "hostname": "web-01", "success": true},
    {"host_id": 2, "hostname": "web-02", "success": true},
    {"host_id": 3, "success": false, "error": "Windows host requires windows_domain account"}
  ]
}
```

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
  -X POST http://localhost:5050/auth/login \
  -d "username=admin&password=secret"

# Create host
curl -b cookies.txt \
  -X POST http://localhost:5050/api/hosts \
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
  -X POST http://localhost:5050/api/hosts/1/scan

# Run AV scan
curl -b cookies.txt \
  -X POST http://localhost:5050/api/hosts/1/av-scan \
  -H "Content-Type: application/json" \
  -d '{"scan_type": "full"}'
```

---

## 🐍 Example: Python Client

```python
import requests

# Create session
session = requests.Session()
base_url = "http://localhost:5050"

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
