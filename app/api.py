from flask import Blueprint, jsonify, request
from flask_login import login_required, current_user
from functools import wraps
from datetime import datetime, timedelta
import json
from sqlalchemy import func, or_
from app import db
from app.models import Host, ScanResult, AVScanResult, User
from app.scanner import RemoteScanner
from app.av_scanner import ClamAVScanner

api_bp = Blueprint('api', __name__)


def admin_required(f):
    """Decorator to require admin privileges."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_admin:
            return jsonify({'error': 'Admin privileges required'}), 403
        return f(*args, **kwargs)
    return decorated_function


@api_bp.route('/hosts', methods=['GET'])
@login_required
def list_hosts():
    """List all hosts for the current user."""
    hosts = Host.query.filter_by(user_id=current_user.id).all()
    return jsonify([h.to_dict() for h in hosts])


@api_bp.route('/hosts', methods=['POST'])
@login_required
def create_host():
    """Create a new host."""
    data = request.get_json()

    if not data or 'hostname' not in data:
        return jsonify({'error': 'hostname is required'}), 400

    host = Host(
        hostname=data['hostname'],
        ip_address=data.get('ip_address'),
        os_type=data.get('os_type', 'linux'),
        ssh_port=data.get('ssh_port', 22),
        winrm_port=data.get('winrm_port', 5985),
        username=data.get('username'),
        password_encrypted=data.get('password'),
        ssh_key=data.get('ssh_key'),
        user_id=current_user.id
    )

    db.session.add(host)
    db.session.commit()

    return jsonify(host.to_dict()), 201


@api_bp.route('/hosts/<int:host_id>', methods=['GET'])
@login_required
def get_host(host_id):
    """Get a specific host."""
    host = Host.query.filter_by(id=host_id, user_id=current_user.id).first()
    if not host:
        return jsonify({'error': 'Host not found'}), 404
    return jsonify(host.to_dict())


@api_bp.route('/hosts/<int:host_id>', methods=['PUT'])
@login_required
def update_host(host_id):
    """Update a host."""
    host = Host.query.filter_by(id=host_id, user_id=current_user.id).first()
    if not host:
        return jsonify({'error': 'Host not found'}), 404

    data = request.get_json()

    if 'hostname' in data:
        host.hostname = data['hostname']
    if 'ip_address' in data:
        host.ip_address = data['ip_address']
    if 'os_type' in data:
        host.os_type = data['os_type']
    if 'ssh_port' in data:
        host.ssh_port = data['ssh_port']
    if 'winrm_port' in data:
        host.winrm_port = data['winrm_port']
    if 'username' in data:
        host.username = data['username']
    if 'password' in data:
        host.password_encrypted = data['password']
    if 'ssh_key' in data:
        host.ssh_key = data['ssh_key']

    db.session.commit()
    return jsonify(host.to_dict())


@api_bp.route('/hosts/<int:host_id>', methods=['DELETE'])
@login_required
def delete_host(host_id):
    """Delete a host."""
    host = Host.query.filter_by(id=host_id, user_id=current_user.id).first()
    if not host:
        return jsonify({'error': 'Host not found'}), 404

    ScanResult.query.filter_by(host_id=host.id).delete()
    AVScanResult.query.filter_by(host_id=host.id).delete()
    db.session.delete(host)
    db.session.commit()

    return jsonify({'message': 'Host deleted'}), 200


@api_bp.route('/hosts/<int:host_id>/scan', methods=['POST'])
@login_required
def scan_host(host_id):
    """Trigger a scan for a host."""
    host = Host.query.filter_by(id=host_id, user_id=current_user.id).first()
    if not host:
        return jsonify({'error': 'Host not found'}), 404

    data = request.get_json() or {}
    password = data.get('password')

    scanner = RemoteScanner(host, password)
    result = scanner.scan()

    return jsonify(result.to_dict())


@api_bp.route('/hosts/<int:host_id>/scans', methods=['GET'])
@login_required
def list_scans(host_id):
    """List scan history for a host."""
    host = Host.query.filter_by(id=host_id, user_id=current_user.id).first()
    if not host:
        return jsonify({'error': 'Host not found'}), 404

    limit = request.args.get('limit', 20, type=int)
    scans = ScanResult.query.filter_by(host_id=host.id).order_by(
        ScanResult.created_at.desc()
    ).limit(limit).all()

    return jsonify([s.to_dict() for s in scans])


@api_bp.route('/hosts/<int:host_id>/scans/<int:scan_id>', methods=['GET'])
@login_required
def get_scan(host_id, scan_id):
    """Get a specific scan result."""
    host = Host.query.filter_by(id=host_id, user_id=current_user.id).first()
    if not host:
        return jsonify({'error': 'Host not found'}), 404

    scan = ScanResult.query.filter_by(id=scan_id, host_id=host.id).first()
    if not scan:
        return jsonify({'error': 'Scan not found'}), 404

    return jsonify(scan.to_dict())


@api_bp.route('/dashboard/stats', methods=['GET'])
@login_required
def dashboard_stats():
    """Get dashboard statistics."""
    hosts = Host.query.filter_by(user_id=current_user.id).all()

    return jsonify({
        'total_hosts': len(hosts),
        'online_hosts': sum(1 for h in hosts if h.status == 'online'),
        'offline_hosts': sum(1 for h in hosts if h.status == 'offline'),
        'error_hosts': sum(1 for h in hosts if h.status == 'error'),
        'pending_hosts': sum(1 for h in hosts if h.status == 'pending')
    })


@api_bp.route('/hosts/<int:host_id>/av-scan', methods=['POST'])
@login_required
def av_scan_host(host_id):
    """Trigger an antivirus scan for a host."""
    host = Host.query.filter_by(id=host_id, user_id=current_user.id).first()
    if not host:
        return jsonify({'error': 'Host not found'}), 404

    data = request.get_json() or {}
    scan_type = data.get('scan_type', 'quick')
    paths = data.get('paths')
    password = data.get('password')

    scanner = ClamAVScanner(host, password)
    result = scanner.scan(paths=paths, scan_type=scan_type)

    return jsonify(result.to_dict())


@api_bp.route('/hosts/<int:host_id>/av-scans', methods=['GET'])
@login_required
def list_av_scans(host_id):
    """List AV scan history for a host."""
    host = Host.query.filter_by(id=host_id, user_id=current_user.id).first()
    if not host:
        return jsonify({'error': 'Host not found'}), 404

    limit = request.args.get('limit', 20, type=int)
    scans = AVScanResult.query.filter_by(host_id=host.id).order_by(
        AVScanResult.created_at.desc()
    ).limit(limit).all()

    return jsonify([s.to_dict() for s in scans])


@api_bp.route('/hosts/<int:host_id>/av-scans/<int:scan_id>', methods=['GET'])
@login_required
def get_av_scan(host_id, scan_id):
    """Get a specific AV scan result."""
    host = Host.query.filter_by(id=host_id, user_id=current_user.id).first()
    if not host:
        return jsonify({'error': 'Host not found'}), 404

    scan = AVScanResult.query.filter_by(id=scan_id, host_id=host.id).first()
    if not scan:
        return jsonify({'error': 'AV scan not found'}), 404

    return jsonify(scan.to_dict())


# =============================================================================
# USER MANAGEMENT ENDPOINTS
# =============================================================================

@api_bp.route('/users/me', methods=['GET'])
@login_required
def get_current_user():
    """Get the current user's profile."""
    return jsonify({
        'id': current_user.id,
        'username': current_user.username,
        'email': current_user.email,
        'is_admin': current_user.is_admin,
        'created_at': current_user.created_at.isoformat(),
        'host_count': Host.query.filter_by(user_id=current_user.id).count()
    })


@api_bp.route('/users/me', methods=['PUT'])
@login_required
def update_current_user():
    """Update the current user's profile."""
    data = request.get_json()

    if 'email' in data:
        existing = User.query.filter(
            User.email == data['email'],
            User.id != current_user.id
        ).first()
        if existing:
            return jsonify({'error': 'Email already in use'}), 400
        current_user.email = data['email']

    if 'username' in data:
        existing = User.query.filter(
            User.username == data['username'],
            User.id != current_user.id
        ).first()
        if existing:
            return jsonify({'error': 'Username already in use'}), 400
        current_user.username = data['username']

    db.session.commit()
    return jsonify({
        'id': current_user.id,
        'username': current_user.username,
        'email': current_user.email,
        'is_admin': current_user.is_admin
    })


@api_bp.route('/users/me/password', methods=['PUT'])
@login_required
def change_password():
    """Change the current user's password."""
    data = request.get_json()

    if not data or 'current_password' not in data or 'new_password' not in data:
        return jsonify({'error': 'current_password and new_password are required'}), 400

    if not current_user.check_password(data['current_password']):
        return jsonify({'error': 'Current password is incorrect'}), 401

    if len(data['new_password']) < 8:
        return jsonify({'error': 'New password must be at least 8 characters'}), 400

    current_user.set_password(data['new_password'])
    db.session.commit()

    return jsonify({'message': 'Password changed successfully'})


@api_bp.route('/users', methods=['GET'])
@login_required
@admin_required
def list_users():
    """List all users (admin only)."""
    users = User.query.all()
    return jsonify([{
        'id': u.id,
        'username': u.username,
        'email': u.email,
        'is_admin': u.is_admin,
        'created_at': u.created_at.isoformat(),
        'host_count': Host.query.filter_by(user_id=u.id).count()
    } for u in users])


@api_bp.route('/users/<int:user_id>', methods=['GET'])
@login_required
@admin_required
def get_user(user_id):
    """Get a specific user (admin only)."""
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404

    return jsonify({
        'id': user.id,
        'username': user.username,
        'email': user.email,
        'is_admin': user.is_admin,
        'created_at': user.created_at.isoformat(),
        'host_count': Host.query.filter_by(user_id=user.id).count()
    })


@api_bp.route('/users/<int:user_id>', methods=['DELETE'])
@login_required
@admin_required
def delete_user(user_id):
    """Delete a user and all their data (admin only)."""
    if user_id == current_user.id:
        return jsonify({'error': 'Cannot delete yourself'}), 400

    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404

    # Delete all user's hosts and associated scan data
    hosts = Host.query.filter_by(user_id=user.id).all()
    for host in hosts:
        ScanResult.query.filter_by(host_id=host.id).delete()
        AVScanResult.query.filter_by(host_id=host.id).delete()
        db.session.delete(host)

    db.session.delete(user)
    db.session.commit()

    return jsonify({'message': 'User deleted successfully'})


# =============================================================================
# BULK OPERATIONS ENDPOINTS
# =============================================================================

@api_bp.route('/hosts/bulk-scan', methods=['POST'])
@login_required
def bulk_scan():
    """Trigger health scans for multiple hosts."""
    data = request.get_json()

    if not data or 'host_ids' not in data:
        return jsonify({'error': 'host_ids array is required'}), 400

    host_ids = data['host_ids']
    password = data.get('password')
    results = []

    for host_id in host_ids:
        host = Host.query.filter_by(id=host_id, user_id=current_user.id).first()
        if not host:
            results.append({
                'host_id': host_id,
                'success': False,
                'error': 'Host not found'
            })
            continue

        try:
            scanner = RemoteScanner(host, password)
            result = scanner.scan()
            results.append({
                'host_id': host_id,
                'success': result.success,
                'scan_id': result.id,
                'error': result.error_message
            })
        except Exception as e:
            results.append({
                'host_id': host_id,
                'success': False,
                'error': str(e)
            })

    return jsonify({
        'total': len(host_ids),
        'successful': sum(1 for r in results if r['success']),
        'failed': sum(1 for r in results if not r['success']),
        'results': results
    })


@api_bp.route('/hosts/bulk-av-scan', methods=['POST'])
@login_required
def bulk_av_scan():
    """Trigger AV scans for multiple hosts."""
    data = request.get_json()

    if not data or 'host_ids' not in data:
        return jsonify({'error': 'host_ids array is required'}), 400

    host_ids = data['host_ids']
    scan_type = data.get('scan_type', 'quick')
    password = data.get('password')
    results = []

    for host_id in host_ids:
        host = Host.query.filter_by(id=host_id, user_id=current_user.id).first()
        if not host:
            results.append({
                'host_id': host_id,
                'success': False,
                'error': 'Host not found'
            })
            continue

        try:
            scanner = ClamAVScanner(host, password)
            result = scanner.scan(scan_type=scan_type)
            results.append({
                'host_id': host_id,
                'success': result.success,
                'scan_id': result.id,
                'threats_found': result.threats_found,
                'error': result.error_message
            })
        except Exception as e:
            results.append({
                'host_id': host_id,
                'success': False,
                'error': str(e)
            })

    return jsonify({
        'total': len(host_ids),
        'successful': sum(1 for r in results if r['success']),
        'failed': sum(1 for r in results if not r['success']),
        'total_threats': sum(r.get('threats_found', 0) for r in results),
        'results': results
    })


# =============================================================================
# ADVANCED DASHBOARD & ANALYTICS ENDPOINTS
# =============================================================================

@api_bp.route('/dashboard/overview', methods=['GET'])
@login_required
def dashboard_overview():
    """Get comprehensive dashboard overview with recent activity."""
    hosts = Host.query.filter_by(user_id=current_user.id).all()
    host_ids = [h.id for h in hosts]

    # Recent scans (last 24 hours)
    yesterday = datetime.utcnow() - timedelta(hours=24)
    recent_scans = ScanResult.query.filter(
        ScanResult.host_id.in_(host_ids),
        ScanResult.created_at >= yesterday
    ).count()

    recent_av_scans = AVScanResult.query.filter(
        AVScanResult.host_id.in_(host_ids),
        AVScanResult.created_at >= yesterday
    ).count()

    # Threat statistics
    total_threats = db.session.query(func.sum(AVScanResult.threats_found)).filter(
        AVScanResult.host_id.in_(host_ids)
    ).scalar() or 0

    recent_threats = db.session.query(func.sum(AVScanResult.threats_found)).filter(
        AVScanResult.host_id.in_(host_ids),
        AVScanResult.created_at >= yesterday
    ).scalar() or 0

    # Latest scan results
    latest_scans = ScanResult.query.filter(
        ScanResult.host_id.in_(host_ids)
    ).order_by(ScanResult.created_at.desc()).limit(5).all()

    # Hosts with issues (high CPU, memory, or threats)
    hosts_with_issues = []
    for host in hosts:
        latest_scan = ScanResult.query.filter_by(
            host_id=host.id
        ).order_by(ScanResult.created_at.desc()).first()

        if latest_scan and latest_scan.success:
            issues = []
            if latest_scan.cpu_usage and latest_scan.cpu_usage > 80:
                issues.append(f'High CPU: {latest_scan.cpu_usage:.1f}%')
            if latest_scan.memory_percent and latest_scan.memory_percent > 80:
                issues.append(f'High Memory: {latest_scan.memory_percent:.1f}%')
            if issues:
                hosts_with_issues.append({
                    'host_id': host.id,
                    'hostname': host.hostname,
                    'issues': issues
                })

    return jsonify({
        'host_stats': {
            'total': len(hosts),
            'online': sum(1 for h in hosts if h.status == 'online'),
            'offline': sum(1 for h in hosts if h.status == 'offline'),
            'error': sum(1 for h in hosts if h.status == 'error'),
            'pending': sum(1 for h in hosts if h.status == 'pending')
        },
        'scan_activity': {
            'health_scans_24h': recent_scans,
            'av_scans_24h': recent_av_scans
        },
        'threat_stats': {
            'total_threats_found': total_threats,
            'threats_last_24h': recent_threats
        },
        'recent_scans': [{
            'id': s.id,
            'host_id': s.host_id,
            'success': s.success,
            'cpu_usage': s.cpu_usage,
            'memory_percent': s.memory_percent,
            'created_at': s.created_at.isoformat()
        } for s in latest_scans],
        'hosts_with_issues': hosts_with_issues
    })


@api_bp.route('/hosts/<int:host_id>/metrics/history', methods=['GET'])
@login_required
def get_metrics_history(host_id):
    """Get historical metrics for a host (for graphing)."""
    host = Host.query.filter_by(id=host_id, user_id=current_user.id).first()
    if not host:
        return jsonify({'error': 'Host not found'}), 404

    # Get time range from query params
    hours = request.args.get('hours', 24, type=int)
    limit = request.args.get('limit', 100, type=int)
    since = datetime.utcnow() - timedelta(hours=hours)

    scans = ScanResult.query.filter(
        ScanResult.host_id == host.id,
        ScanResult.created_at >= since,
        ScanResult.success == True
    ).order_by(ScanResult.created_at.asc()).limit(limit).all()

    return jsonify({
        'host_id': host_id,
        'hostname': host.hostname,
        'period_hours': hours,
        'data_points': len(scans),
        'metrics': [{
            'timestamp': s.created_at.isoformat(),
            'cpu_usage': s.cpu_usage,
            'memory_percent': s.memory_percent,
            'memory_used': s.memory_used,
            'memory_total': s.memory_total,
            'process_count': s.process_count
        } for s in scans]
    })


@api_bp.route('/hosts/<int:host_id>/health-score', methods=['GET'])
@login_required
def get_health_score(host_id):
    """Calculate and return a health score for a host."""
    host = Host.query.filter_by(id=host_id, user_id=current_user.id).first()
    if not host:
        return jsonify({'error': 'Host not found'}), 404

    # Get latest successful scan
    latest_scan = ScanResult.query.filter_by(
        host_id=host.id,
        success=True
    ).order_by(ScanResult.created_at.desc()).first()

    if not latest_scan:
        return jsonify({
            'host_id': host_id,
            'hostname': host.hostname,
            'health_score': None,
            'status': 'no_data',
            'message': 'No successful scan data available'
        })

    # Calculate health score (0-100)
    score = 100
    factors = []

    # CPU factor (deduct up to 30 points)
    if latest_scan.cpu_usage:
        if latest_scan.cpu_usage > 90:
            score -= 30
            factors.append({'factor': 'cpu', 'impact': -30, 'value': latest_scan.cpu_usage})
        elif latest_scan.cpu_usage > 80:
            score -= 20
            factors.append({'factor': 'cpu', 'impact': -20, 'value': latest_scan.cpu_usage})
        elif latest_scan.cpu_usage > 70:
            score -= 10
            factors.append({'factor': 'cpu', 'impact': -10, 'value': latest_scan.cpu_usage})

    # Memory factor (deduct up to 30 points)
    if latest_scan.memory_percent:
        if latest_scan.memory_percent > 90:
            score -= 30
            factors.append({'factor': 'memory', 'impact': -30, 'value': latest_scan.memory_percent})
        elif latest_scan.memory_percent > 80:
            score -= 20
            factors.append({'factor': 'memory', 'impact': -20, 'value': latest_scan.memory_percent})
        elif latest_scan.memory_percent > 70:
            score -= 10
            factors.append({'factor': 'memory', 'impact': -10, 'value': latest_scan.memory_percent})

    # Host status factor (deduct up to 20 points)
    if host.status == 'error':
        score -= 20
        factors.append({'factor': 'status', 'impact': -20, 'value': host.status})
    elif host.status == 'offline':
        score -= 10
        factors.append({'factor': 'status', 'impact': -10, 'value': host.status})

    # Recent threats factor (deduct up to 20 points)
    recent_threats = db.session.query(func.sum(AVScanResult.threats_found)).filter(
        AVScanResult.host_id == host.id,
        AVScanResult.created_at >= datetime.utcnow() - timedelta(days=7)
    ).scalar() or 0

    if recent_threats > 0:
        threat_penalty = min(20, recent_threats * 5)
        score -= threat_penalty
        factors.append({'factor': 'threats', 'impact': -threat_penalty, 'value': recent_threats})

    # Ensure score is between 0 and 100
    score = max(0, min(100, score))

    # Determine status
    if score >= 80:
        status = 'healthy'
    elif score >= 60:
        status = 'warning'
    else:
        status = 'critical'

    return jsonify({
        'host_id': host_id,
        'hostname': host.hostname,
        'health_score': score,
        'status': status,
        'factors': factors,
        'last_scan': latest_scan.created_at.isoformat()
    })


# =============================================================================
# THREAT ANALYTICS ENDPOINTS
# =============================================================================

@api_bp.route('/threats/summary', methods=['GET'])
@login_required
def threats_summary():
    """Get a summary of all threats across user's hosts."""
    hosts = Host.query.filter_by(user_id=current_user.id).all()
    host_ids = [h.id for h in hosts]

    # Get all AV scans with threats
    scans_with_threats = AVScanResult.query.filter(
        AVScanResult.host_id.in_(host_ids),
        AVScanResult.threats_found > 0
    ).order_by(AVScanResult.created_at.desc()).all()

    # Aggregate by host
    hosts_summary = {}
    for scan in scans_with_threats:
        if scan.host_id not in hosts_summary:
            host = next(h for h in hosts if h.id == scan.host_id)
            hosts_summary[scan.host_id] = {
                'host_id': scan.host_id,
                'hostname': host.hostname,
                'total_threats': 0,
                'scan_count': 0,
                'latest_scan': None
            }
        hosts_summary[scan.host_id]['total_threats'] += scan.threats_found
        hosts_summary[scan.host_id]['scan_count'] += 1
        if not hosts_summary[scan.host_id]['latest_scan']:
            hosts_summary[scan.host_id]['latest_scan'] = scan.created_at.isoformat()

    total_threats = sum(h['total_threats'] for h in hosts_summary.values())

    return jsonify({
        'total_threats': total_threats,
        'hosts_affected': len(hosts_summary),
        'total_hosts': len(hosts),
        'by_host': list(hosts_summary.values())
    })


@api_bp.route('/threats/recent', methods=['GET'])
@login_required
def recent_threats():
    """Get recent threat detections."""
    hosts = Host.query.filter_by(user_id=current_user.id).all()
    host_ids = [h.id for h in hosts]
    host_map = {h.id: h.hostname for h in hosts}

    limit = request.args.get('limit', 20, type=int)
    days = request.args.get('days', 7, type=int)
    since = datetime.utcnow() - timedelta(days=days)

    scans = AVScanResult.query.filter(
        AVScanResult.host_id.in_(host_ids),
        AVScanResult.threats_found > 0,
        AVScanResult.created_at >= since
    ).order_by(AVScanResult.created_at.desc()).limit(limit).all()

    return jsonify({
        'period_days': days,
        'total_results': len(scans),
        'threats': [{
            'scan_id': s.id,
            'host_id': s.host_id,
            'hostname': host_map.get(s.host_id),
            'scan_type': s.scan_type,
            'threats_found': s.threats_found,
            'threat_details': s.threat_details,
            'created_at': s.created_at.isoformat()
        } for s in scans]
    })


# =============================================================================
# SEARCH & FILTERING ENDPOINTS
# =============================================================================

@api_bp.route('/hosts/search', methods=['GET'])
@login_required
def search_hosts():
    """Search hosts with filters."""
    query = Host.query.filter_by(user_id=current_user.id)

    # Filter by hostname (partial match)
    hostname = request.args.get('hostname')
    if hostname:
        query = query.filter(Host.hostname.ilike(f'%{hostname}%'))

    # Filter by status
    status = request.args.get('status')
    if status:
        query = query.filter(Host.status == status)

    # Filter by OS type
    os_type = request.args.get('os_type')
    if os_type:
        query = query.filter(Host.os_type == os_type)

    # Filter by IP (partial match)
    ip = request.args.get('ip')
    if ip:
        query = query.filter(Host.ip_address.ilike(f'%{ip}%'))

    # Sorting
    sort_by = request.args.get('sort_by', 'hostname')
    sort_order = request.args.get('sort_order', 'asc')

    if sort_by == 'hostname':
        order_col = Host.hostname
    elif sort_by == 'status':
        order_col = Host.status
    elif sort_by == 'last_scan':
        order_col = Host.last_scan
    elif sort_by == 'created_at':
        order_col = Host.created_at
    else:
        order_col = Host.hostname

    if sort_order == 'desc':
        query = query.order_by(order_col.desc())
    else:
        query = query.order_by(order_col.asc())

    # Pagination
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)

    paginated = query.paginate(page=page, per_page=per_page, error_out=False)

    return jsonify({
        'hosts': [h.to_dict() for h in paginated.items],
        'pagination': {
            'page': paginated.page,
            'per_page': paginated.per_page,
            'total_pages': paginated.pages,
            'total_items': paginated.total
        }
    })


@api_bp.route('/scans/search', methods=['GET'])
@login_required
def search_scans():
    """Search scan results with filters."""
    hosts = Host.query.filter_by(user_id=current_user.id).all()
    host_ids = [h.id for h in hosts]

    query = ScanResult.query.filter(ScanResult.host_id.in_(host_ids))

    # Filter by host
    host_id = request.args.get('host_id', type=int)
    if host_id and host_id in host_ids:
        query = query.filter(ScanResult.host_id == host_id)

    # Filter by success
    success = request.args.get('success')
    if success is not None:
        query = query.filter(ScanResult.success == (success.lower() == 'true'))

    # Filter by date range
    start_date = request.args.get('start_date')
    if start_date:
        try:
            start = datetime.fromisoformat(start_date)
            query = query.filter(ScanResult.created_at >= start)
        except ValueError:
            pass

    end_date = request.args.get('end_date')
    if end_date:
        try:
            end = datetime.fromisoformat(end_date)
            query = query.filter(ScanResult.created_at <= end)
        except ValueError:
            pass

    # Filter by CPU threshold
    min_cpu = request.args.get('min_cpu', type=float)
    if min_cpu is not None:
        query = query.filter(ScanResult.cpu_usage >= min_cpu)

    # Filter by memory threshold
    min_memory = request.args.get('min_memory', type=float)
    if min_memory is not None:
        query = query.filter(ScanResult.memory_percent >= min_memory)

    # Sorting
    query = query.order_by(ScanResult.created_at.desc())

    # Pagination
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)

    paginated = query.paginate(page=page, per_page=per_page, error_out=False)

    return jsonify({
        'scans': [s.to_dict() for s in paginated.items],
        'pagination': {
            'page': paginated.page,
            'per_page': paginated.per_page,
            'total_pages': paginated.pages,
            'total_items': paginated.total
        }
    })


# =============================================================================
# EXPORT ENDPOINTS
# =============================================================================

@api_bp.route('/export/hosts', methods=['GET'])
@login_required
def export_hosts():
    """Export all hosts data as JSON."""
    hosts = Host.query.filter_by(user_id=current_user.id).all()

    export_data = []
    for host in hosts:
        host_data = host.to_dict()

        # Include latest scan if requested
        if request.args.get('include_latest_scan', 'false').lower() == 'true':
            latest_scan = ScanResult.query.filter_by(
                host_id=host.id
            ).order_by(ScanResult.created_at.desc()).first()
            if latest_scan:
                host_data['latest_scan'] = latest_scan.to_dict()

        # Include latest AV scan if requested
        if request.args.get('include_latest_av_scan', 'false').lower() == 'true':
            latest_av = AVScanResult.query.filter_by(
                host_id=host.id
            ).order_by(AVScanResult.created_at.desc()).first()
            if latest_av:
                host_data['latest_av_scan'] = latest_av.to_dict()

        export_data.append(host_data)

    return jsonify({
        'exported_at': datetime.utcnow().isoformat(),
        'user': current_user.username,
        'total_hosts': len(export_data),
        'hosts': export_data
    })


@api_bp.route('/export/scans', methods=['GET'])
@login_required
def export_scans():
    """Export scan results as JSON."""
    hosts = Host.query.filter_by(user_id=current_user.id).all()
    host_ids = [h.id for h in hosts]
    host_map = {h.id: h.hostname for h in hosts}

    # Filter by date range
    days = request.args.get('days', 30, type=int)
    since = datetime.utcnow() - timedelta(days=days)

    scans = ScanResult.query.filter(
        ScanResult.host_id.in_(host_ids),
        ScanResult.created_at >= since
    ).order_by(ScanResult.created_at.desc()).all()

    export_data = []
    for scan in scans:
        scan_data = scan.to_dict()
        scan_data['hostname'] = host_map.get(scan.host_id)
        export_data.append(scan_data)

    return jsonify({
        'exported_at': datetime.utcnow().isoformat(),
        'user': current_user.username,
        'period_days': days,
        'total_scans': len(export_data),
        'scans': export_data
    })


@api_bp.route('/export/av-scans', methods=['GET'])
@login_required
def export_av_scans():
    """Export AV scan results as JSON."""
    hosts = Host.query.filter_by(user_id=current_user.id).all()
    host_ids = [h.id for h in hosts]
    host_map = {h.id: h.hostname for h in hosts}

    # Filter by date range
    days = request.args.get('days', 30, type=int)
    since = datetime.utcnow() - timedelta(days=days)

    # Option to only export scans with threats
    threats_only = request.args.get('threats_only', 'false').lower() == 'true'

    query = AVScanResult.query.filter(
        AVScanResult.host_id.in_(host_ids),
        AVScanResult.created_at >= since
    )

    if threats_only:
        query = query.filter(AVScanResult.threats_found > 0)

    scans = query.order_by(AVScanResult.created_at.desc()).all()

    export_data = []
    for scan in scans:
        scan_data = scan.to_dict()
        scan_data['hostname'] = host_map.get(scan.host_id)
        export_data.append(scan_data)

    return jsonify({
        'exported_at': datetime.utcnow().isoformat(),
        'user': current_user.username,
        'period_days': days,
        'threats_only': threats_only,
        'total_scans': len(export_data),
        'total_threats': sum(s.threats_found for s in scans),
        'scans': export_data
    })


# =============================================================================
# SERVER COMPARISON ENDPOINTS
# =============================================================================

@api_bp.route('/compare/hosts', methods=['POST'])
@login_required
def compare_hosts():
    """Compare two or more hosts side by side."""
    data = request.get_json()

    if not data or 'host_ids' not in data:
        return jsonify({'error': 'host_ids array is required'}), 400

    host_ids = data['host_ids']
    if len(host_ids) < 2:
        return jsonify({'error': 'At least 2 host_ids required for comparison'}), 400

    # Verify all hosts belong to user
    hosts = []
    for host_id in host_ids:
        host = Host.query.filter_by(id=host_id, user_id=current_user.id).first()
        if not host:
            return jsonify({'error': f'Host {host_id} not found'}), 404
        hosts.append(host)

    # Get latest scan for each host
    comparisons = []
    for host in hosts:
        latest_scan = ScanResult.query.filter_by(
            host_id=host.id,
            success=True
        ).order_by(ScanResult.created_at.desc()).first()

        if latest_scan:
            # Parse system snapshot
            try:
                snapshot = json.loads(latest_scan.system_snapshot) if latest_scan.system_snapshot else {}
            except json.JSONDecodeError:
                snapshot = {}

            comparisons.append({
                'host_id': host.id,
                'hostname': host.hostname,
                'os_type': host.os_type,
                'status': host.status,
                'last_scan': latest_scan.created_at.isoformat(),
                'snapshot': snapshot,
                'metrics': {
                    'cpu_usage': latest_scan.cpu_usage,
                    'memory_percent': latest_scan.memory_percent,
                    'memory_total': latest_scan.memory_total,
                    'memory_used': latest_scan.memory_used,
                    'process_count': latest_scan.process_count,
                    'uptime': latest_scan.uptime
                },
                'system': {
                    'os_info': latest_scan.os_info,
                    'kernel_version': latest_scan.kernel_version,
                    'build_info': latest_scan.build_info
                },
                'updates': {
                    'pending_updates': latest_scan.pending_updates,
                    'last_update_check': latest_scan.last_update_check
                },
                'drivers': {
                    'driver_info': latest_scan.driver_info,
                    'driver_updates': latest_scan.driver_updates
                }
            })
        else:
            comparisons.append({
                'host_id': host.id,
                'hostname': host.hostname,
                'os_type': host.os_type,
                'status': host.status,
                'last_scan': None,
                'snapshot': {},
                'metrics': None,
                'system': None,
                'updates': None,
                'drivers': None
            })

    # Build comparison summary highlighting differences
    differences = _find_differences(comparisons)

    return jsonify({
        'compared_at': datetime.utcnow().isoformat(),
        'host_count': len(hosts),
        'hosts': comparisons,
        'differences': differences
    })


def _find_differences(comparisons):
    """Find key differences between compared hosts."""
    differences = {
        'os_version_mismatch': False,
        'kernel_mismatch': False,
        'update_status_varies': False,
        'memory_difference_significant': False,
        'cpu_difference_significant': False,
        'details': []
    }

    if len(comparisons) < 2:
        return differences

    # Get snapshots
    snapshots = [c.get('snapshot', {}) for c in comparisons if c.get('snapshot')]

    if len(snapshots) >= 2:
        # Check OS version
        os_versions = set(s.get('os_version', '') for s in snapshots if s.get('os_version'))
        if len(os_versions) > 1:
            differences['os_version_mismatch'] = True
            differences['details'].append({
                'type': 'os_version',
                'message': f'OS versions differ: {", ".join(os_versions)}'
            })

        # Check kernel version
        kernel_versions = set(s.get('kernel_version', '') for s in snapshots if s.get('kernel_version'))
        if len(kernel_versions) > 1:
            differences['kernel_mismatch'] = True
            differences['details'].append({
                'type': 'kernel_version',
                'message': f'Kernel versions differ: {", ".join(kernel_versions)}'
            })

        # Check pending updates
        update_counts = [s.get('pending_update_count', 0) for s in snapshots]
        if max(update_counts) - min(update_counts) > 5:
            differences['update_status_varies'] = True
            differences['details'].append({
                'type': 'pending_updates',
                'message': f'Update counts vary significantly: {update_counts}'
            })

        # Check CPU usage difference
        cpu_values = [s.get('cpu_usage') for s in snapshots if s.get('cpu_usage') is not None]
        if cpu_values and max(cpu_values) - min(cpu_values) > 30:
            differences['cpu_difference_significant'] = True
            differences['details'].append({
                'type': 'cpu_usage',
                'message': f'CPU usage varies significantly: {cpu_values}'
            })

        # Check memory usage difference
        mem_values = [s.get('memory_percent') for s in snapshots if s.get('memory_percent') is not None]
        if mem_values and max(mem_values) - min(mem_values) > 30:
            differences['memory_difference_significant'] = True
            differences['details'].append({
                'type': 'memory_percent',
                'message': f'Memory usage varies significantly: {mem_values}'
            })

    return differences


@api_bp.route('/compare/events', methods=['POST'])
@login_required
def compare_events():
    """Compare event logs between two or more hosts."""
    data = request.get_json()

    if not data or 'host_ids' not in data:
        return jsonify({'error': 'host_ids array is required'}), 400

    host_ids = data['host_ids']
    event_type = data.get('event_type', 'all')  # all, security, system, application, critical

    # Verify all hosts belong to user
    hosts = []
    for host_id in host_ids:
        host = Host.query.filter_by(id=host_id, user_id=current_user.id).first()
        if not host:
            return jsonify({'error': f'Host {host_id} not found'}), 404
        hosts.append(host)

    # Get latest scan for each host
    event_comparisons = []
    for host in hosts:
        latest_scan = ScanResult.query.filter_by(
            host_id=host.id,
            success=True
        ).order_by(ScanResult.created_at.desc()).first()

        host_events = {
            'host_id': host.id,
            'hostname': host.hostname,
            'os_type': host.os_type,
            'last_scan': latest_scan.created_at.isoformat() if latest_scan else None,
            'events': {}
        }

        if latest_scan:
            if event_type in ['all', 'security']:
                host_events['events']['security'] = latest_scan.security_events
            if event_type in ['all', 'system']:
                host_events['events']['system'] = latest_scan.system_events
            if event_type in ['all', 'application']:
                host_events['events']['application'] = latest_scan.application_events
            if event_type in ['all', 'critical']:
                host_events['events']['critical'] = latest_scan.critical_errors
            host_events['events']['summary'] = latest_scan.event_summary

        event_comparisons.append(host_events)

    return jsonify({
        'compared_at': datetime.utcnow().isoformat(),
        'event_type': event_type,
        'host_count': len(hosts),
        'hosts': event_comparisons
    })


@api_bp.route('/compare/updates', methods=['POST'])
@login_required
def compare_updates():
    """Compare update status between hosts."""
    data = request.get_json()

    if not data or 'host_ids' not in data:
        return jsonify({'error': 'host_ids array is required'}), 400

    host_ids = data['host_ids']

    # Verify all hosts belong to user
    hosts = []
    for host_id in host_ids:
        host = Host.query.filter_by(id=host_id, user_id=current_user.id).first()
        if not host:
            return jsonify({'error': f'Host {host_id} not found'}), 404
        hosts.append(host)

    update_comparisons = []
    for host in hosts:
        latest_scan = ScanResult.query.filter_by(
            host_id=host.id,
            success=True
        ).order_by(ScanResult.created_at.desc()).first()

        host_updates = {
            'host_id': host.id,
            'hostname': host.hostname,
            'os_type': host.os_type,
            'last_scan': latest_scan.created_at.isoformat() if latest_scan else None
        }

        if latest_scan:
            # Parse pending update count
            pending_count = 0
            if latest_scan.pending_updates:
                try:
                    if host.os_type == 'windows':
                        pending_data = json.loads(latest_scan.pending_updates)
                        pending_count = pending_data.get('PendingCount', 0)
                    else:
                        # Count Linux pending updates
                        pending_count = len([l for l in latest_scan.pending_updates.split('\n')
                                           if l.strip() and (l.startswith('Inst') or 'upgrade' in l.lower())])
                except (json.JSONDecodeError, AttributeError):
                    pass

            host_updates['updates'] = {
                'pending_count': pending_count,
                'pending_updates': latest_scan.pending_updates,
                'update_history': latest_scan.update_history,
                'last_update_check': latest_scan.last_update_check,
                'kernel_version': latest_scan.kernel_version,
                'build_info': latest_scan.build_info
            }
        else:
            host_updates['updates'] = None

        update_comparisons.append(host_updates)

    # Find hosts that need updates
    hosts_needing_updates = [
        h for h in update_comparisons
        if h.get('updates') and h['updates'].get('pending_count', 0) > 0
    ]

    return jsonify({
        'compared_at': datetime.utcnow().isoformat(),
        'host_count': len(hosts),
        'hosts_needing_updates': len(hosts_needing_updates),
        'hosts': update_comparisons
    })


@api_bp.route('/compare/drivers', methods=['POST'])
@login_required
def compare_drivers():
    """Compare driver information between hosts."""
    data = request.get_json()

    if not data or 'host_ids' not in data:
        return jsonify({'error': 'host_ids array is required'}), 400

    host_ids = data['host_ids']

    # Verify all hosts belong to user
    hosts = []
    for host_id in host_ids:
        host = Host.query.filter_by(id=host_id, user_id=current_user.id).first()
        if not host:
            return jsonify({'error': f'Host {host_id} not found'}), 404
        hosts.append(host)

    driver_comparisons = []
    for host in hosts:
        latest_scan = ScanResult.query.filter_by(
            host_id=host.id,
            success=True
        ).order_by(ScanResult.created_at.desc()).first()

        host_drivers = {
            'host_id': host.id,
            'hostname': host.hostname,
            'os_type': host.os_type,
            'last_scan': latest_scan.created_at.isoformat() if latest_scan else None
        }

        if latest_scan:
            host_drivers['drivers'] = {
                'driver_info': latest_scan.driver_info,
                'driver_updates': latest_scan.driver_updates
            }
        else:
            host_drivers['drivers'] = None

        driver_comparisons.append(host_drivers)

    return jsonify({
        'compared_at': datetime.utcnow().isoformat(),
        'host_count': len(hosts),
        'hosts': driver_comparisons
    })


# =============================================================================
# AT-A-GLANCE SUMMARY ENDPOINTS
# =============================================================================

@api_bp.route('/hosts/<int:host_id>/summary', methods=['GET'])
@login_required
def get_host_summary(host_id):
    """Get an at-a-glance summary of a host."""
    host = Host.query.filter_by(id=host_id, user_id=current_user.id).first()
    if not host:
        return jsonify({'error': 'Host not found'}), 404

    latest_scan = ScanResult.query.filter_by(
        host_id=host.id,
        success=True
    ).order_by(ScanResult.created_at.desc()).first()

    if not latest_scan:
        return jsonify({
            'host_id': host.id,
            'hostname': host.hostname,
            'status': host.status,
            'os_type': host.os_type,
            'has_scan_data': False,
            'message': 'No successful scan data available'
        })

    # Parse system snapshot
    try:
        snapshot = json.loads(latest_scan.system_snapshot) if latest_scan.system_snapshot else {}
    except json.JSONDecodeError:
        snapshot = {}

    # Parse pending updates
    pending_count = 0
    if latest_scan.pending_updates:
        try:
            if host.os_type == 'windows':
                pending_data = json.loads(latest_scan.pending_updates)
                pending_count = pending_data.get('PendingCount', 0)
            else:
                pending_count = len([l for l in latest_scan.pending_updates.split('\n')
                                   if l.strip() and l.startswith('Inst')])
        except (json.JSONDecodeError, AttributeError):
            pass

    # Get threat count from recent AV scans
    recent_threats = db.session.query(func.sum(AVScanResult.threats_found)).filter(
        AVScanResult.host_id == host.id,
        AVScanResult.created_at >= datetime.utcnow() - timedelta(days=7)
    ).scalar() or 0

    # Determine health indicators
    health_warnings = []
    if latest_scan.cpu_usage and latest_scan.cpu_usage > 80:
        health_warnings.append(f'High CPU: {latest_scan.cpu_usage:.1f}%')
    if latest_scan.memory_percent and latest_scan.memory_percent > 80:
        health_warnings.append(f'High Memory: {latest_scan.memory_percent:.1f}%')
    if pending_count > 10:
        health_warnings.append(f'{pending_count} pending updates')
    if recent_threats > 0:
        health_warnings.append(f'{recent_threats} threats detected (7d)')

    return jsonify({
        'host_id': host.id,
        'hostname': host.hostname,
        'status': host.status,
        'os_type': host.os_type,
        'has_scan_data': True,
        'last_scan': latest_scan.created_at.isoformat(),
        'at_a_glance': {
            'os_name': snapshot.get('os_pretty_name', latest_scan.os_info[:50] if latest_scan.os_info else 'Unknown'),
            'os_version': snapshot.get('os_version', ''),
            'kernel_version': latest_scan.kernel_version,
            'build_number': snapshot.get('full_build') or snapshot.get('build_number', ''),
            'uptime': latest_scan.uptime,
            'cpu_usage': latest_scan.cpu_usage,
            'memory_percent': latest_scan.memory_percent,
            'memory_total_gb': snapshot.get('memory_total_gb'),
            'process_count': latest_scan.process_count,
            'pending_updates': pending_count,
            'recent_threats': recent_threats,
            'manufacturer': snapshot.get('manufacturer', ''),
            'model': snapshot.get('model', '')
        },
        'health_warnings': health_warnings,
        'health_status': 'critical' if len(health_warnings) >= 2 else ('warning' if health_warnings else 'healthy')
    })


@api_bp.route('/summary/all', methods=['GET'])
@login_required
def get_all_hosts_summary():
    """Get at-a-glance summaries for all hosts."""
    hosts = Host.query.filter_by(user_id=current_user.id).all()

    summaries = []
    for host in hosts:
        latest_scan = ScanResult.query.filter_by(
            host_id=host.id,
            success=True
        ).order_by(ScanResult.created_at.desc()).first()

        summary = {
            'host_id': host.id,
            'hostname': host.hostname,
            'status': host.status,
            'os_type': host.os_type
        }

        if latest_scan:
            # Parse snapshot
            try:
                snapshot = json.loads(latest_scan.system_snapshot) if latest_scan.system_snapshot else {}
            except json.JSONDecodeError:
                snapshot = {}

            summary['last_scan'] = latest_scan.created_at.isoformat()
            summary['os_name'] = snapshot.get('os_pretty_name', '')
            summary['kernel_version'] = latest_scan.kernel_version
            summary['cpu_usage'] = latest_scan.cpu_usage
            summary['memory_percent'] = latest_scan.memory_percent
            summary['pending_updates'] = snapshot.get('pending_update_count', 0)
        else:
            summary['last_scan'] = None

        summaries.append(summary)

    # Sort by status (error first, then offline, online, pending)
    status_order = {'error': 0, 'offline': 1, 'online': 2, 'pending': 3}
    summaries.sort(key=lambda x: (status_order.get(x['status'], 4), x['hostname']))

    return jsonify({
        'generated_at': datetime.utcnow().isoformat(),
        'total_hosts': len(hosts),
        'by_status': {
            'online': sum(1 for h in hosts if h.status == 'online'),
            'offline': sum(1 for h in hosts if h.status == 'offline'),
            'error': sum(1 for h in hosts if h.status == 'error'),
            'pending': sum(1 for h in hosts if h.status == 'pending')
        },
        'hosts': summaries
    })


@api_bp.route('/summary/updates', methods=['GET'])
@login_required
def get_update_summary():
    """Get a summary of update status across all hosts."""
    hosts = Host.query.filter_by(user_id=current_user.id).all()

    update_summary = {
        'hosts_scanned': 0,
        'hosts_up_to_date': 0,
        'hosts_need_updates': 0,
        'total_pending_updates': 0,
        'by_host': []
    }

    for host in hosts:
        latest_scan = ScanResult.query.filter_by(
            host_id=host.id,
            success=True
        ).order_by(ScanResult.created_at.desc()).first()

        if not latest_scan:
            continue

        update_summary['hosts_scanned'] += 1

        # Parse pending updates
        pending_count = 0
        if latest_scan.pending_updates:
            try:
                if host.os_type == 'windows':
                    pending_data = json.loads(latest_scan.pending_updates)
                    pending_count = pending_data.get('PendingCount', 0)
                else:
                    pending_count = len([l for l in latest_scan.pending_updates.split('\n')
                                       if l.strip() and l.startswith('Inst')])
            except (json.JSONDecodeError, AttributeError):
                pass

        if pending_count > 0:
            update_summary['hosts_need_updates'] += 1
            update_summary['total_pending_updates'] += pending_count
        else:
            update_summary['hosts_up_to_date'] += 1

        update_summary['by_host'].append({
            'host_id': host.id,
            'hostname': host.hostname,
            'os_type': host.os_type,
            'pending_count': pending_count,
            'kernel_version': latest_scan.kernel_version,
            'last_update_check': latest_scan.last_update_check,
            'last_scan': latest_scan.created_at.isoformat()
        })

    # Sort by pending count descending
    update_summary['by_host'].sort(key=lambda x: x['pending_count'], reverse=True)

    return jsonify(update_summary)


@api_bp.route('/summary/versions', methods=['GET'])
@login_required
def get_version_summary():
    """Get a summary of OS and kernel versions across all hosts."""
    hosts = Host.query.filter_by(user_id=current_user.id).all()

    version_groups = {
        'linux': {},
        'windows': {}
    }

    for host in hosts:
        latest_scan = ScanResult.query.filter_by(
            host_id=host.id,
            success=True
        ).order_by(ScanResult.created_at.desc()).first()

        if not latest_scan:
            continue

        # Parse snapshot
        try:
            snapshot = json.loads(latest_scan.system_snapshot) if latest_scan.system_snapshot else {}
        except json.JSONDecodeError:
            snapshot = {}

        os_type = host.os_type
        kernel = latest_scan.kernel_version or 'Unknown'
        os_name = snapshot.get('os_pretty_name', 'Unknown')

        # Group by kernel version
        if kernel not in version_groups[os_type]:
            version_groups[os_type][kernel] = {
                'kernel_version': kernel,
                'os_name': os_name,
                'hosts': []
            }

        version_groups[os_type][kernel]['hosts'].append({
            'host_id': host.id,
            'hostname': host.hostname,
            'os_version': snapshot.get('os_version', ''),
            'build_number': snapshot.get('full_build') or snapshot.get('build_number', '')
        })

    return jsonify({
        'generated_at': datetime.utcnow().isoformat(),
        'linux_versions': list(version_groups['linux'].values()),
        'windows_versions': list(version_groups['windows'].values()),
        'linux_host_count': sum(len(v['hosts']) for v in version_groups['linux'].values()),
        'windows_host_count': sum(len(v['hosts']) for v in version_groups['windows'].values())
    })


# =============================================================================
# DATADOG HOST DATA ENDPOINTS (User-facing)
# =============================================================================

@api_bp.route('/datadog/hosts', methods=['GET'])
@login_required
def get_datadog_hosts():
    """
    Get all Datadog hosts from active integrations.

    Query parameters:
    - integration_id: Filter by specific integration
    - search: Search hosts by name
    - up: Filter by status (true/false)
    - cloud_provider: Filter by cloud provider (aws, azure, gcp)
    - tag: Filter by tag (can be specified multiple times)
    - page: Page number (default 1)
    - per_page: Items per page (default 50, max 200)
    """
    from app.models import DatadogHostCache, DatadogIntegration

    # Check if any integrations are active
    active_integrations = DatadogIntegration.query.filter_by(is_active=True).count()
    if active_integrations == 0:
        return jsonify({
            'hosts': [],
            'total': 0,
            'message': 'No active Datadog integrations configured'
        })

    # Build query
    query = DatadogHostCache.query.join(
        DatadogIntegration,
        DatadogHostCache.integration_id == DatadogIntegration.id
    ).filter(DatadogIntegration.is_active == True)

    # Filter by integration
    integration_id = request.args.get('integration_id', type=int)
    if integration_id:
        query = query.filter(DatadogHostCache.integration_id == integration_id)

    # Search by host name
    search = request.args.get('search')
    if search:
        query = query.filter(DatadogHostCache.host_name.ilike(f'%{search}%'))

    # Filter by status
    up_filter = request.args.get('up')
    if up_filter is not None:
        is_up = up_filter.lower() in ('true', '1', 'yes')
        query = query.filter(DatadogHostCache.up == is_up)

    # Filter by cloud provider
    cloud_provider = request.args.get('cloud_provider')
    if cloud_provider:
        query = query.filter(DatadogHostCache.cloud_provider == cloud_provider)

    # Filter by tag
    tags = request.args.getlist('tag')
    if tags:
        for tag in tags:
            query = query.filter(DatadogHostCache.tags.ilike(f'%{tag}%'))

    # Pagination
    page = request.args.get('page', 1, type=int)
    per_page = min(request.args.get('per_page', 50, type=int), 200)

    # Get total count
    total = query.count()

    # Get paginated results
    hosts = query.order_by(DatadogHostCache.host_name).offset(
        (page - 1) * per_page
    ).limit(per_page).all()

    return jsonify({
        'hosts': [h.to_dict() for h in hosts],
        'total': total,
        'page': page,
        'per_page': per_page,
        'pages': (total + per_page - 1) // per_page
    })


@api_bp.route('/datadog/hosts/<int:host_id>', methods=['GET'])
@login_required
def get_datadog_host(host_id):
    """Get details for a specific Datadog host."""
    from app.models import DatadogHostCache, DatadogIntegration
    import json

    host = DatadogHostCache.query.get(host_id)
    if not host:
        return jsonify({'error': 'Datadog host not found'}), 404

    # Get integration info
    integration = DatadogIntegration.query.get(host.integration_id)

    # Build detailed response
    response = host.to_dict()
    response['integration_name'] = integration.name if integration else None

    # Include full metadata if available
    if host.meta:
        try:
            response['metadata'] = json.loads(host.meta)
        except json.JSONDecodeError:
            pass

    # Include agent checks if available
    if host.agent_checks:
        try:
            response['agent_checks'] = json.loads(host.agent_checks)
        except json.JSONDecodeError:
            pass

    return jsonify(response)


@api_bp.route('/datadog/hosts/<int:host_id>/link', methods=['POST'])
@login_required
def link_datadog_host_to_muse(host_id):
    """Link a Datadog host to a Muse host for combined view."""
    from app.models import DatadogHostCache, Host

    dd_host = DatadogHostCache.query.get(host_id)
    if not dd_host:
        return jsonify({'error': 'Datadog host not found'}), 404

    data = request.get_json()

    if 'muse_host_id' not in data:
        return jsonify({'error': 'muse_host_id is required (use null to unlink)'}), 400

    muse_host_id = data['muse_host_id']

    if muse_host_id is not None:
        muse_host = Host.query.get(muse_host_id)
        if not muse_host:
            return jsonify({'error': 'Muse host not found'}), 404

    dd_host.muse_host_id = muse_host_id
    db.session.commit()

    return jsonify({
        'datadog_host_id': dd_host.id,
        'datadog_host_name': dd_host.host_name,
        'muse_host_id': dd_host.muse_host_id,
        'message': 'Link updated successfully'
    })


@api_bp.route('/datadog/summary', methods=['GET'])
@login_required
def get_datadog_summary():
    """Get summary statistics for all Datadog hosts."""
    from app.models import DatadogHostCache, DatadogIntegration
    from sqlalchemy import func

    # Check for active integrations
    integrations = DatadogIntegration.query.filter_by(is_active=True).all()

    if not integrations:
        return jsonify({
            'integrations': [],
            'total_hosts': 0,
            'hosts_up': 0,
            'hosts_down': 0,
            'message': 'No active Datadog integrations'
        })

    # Get counts
    total_hosts = DatadogHostCache.query.join(
        DatadogIntegration
    ).filter(DatadogIntegration.is_active == True).count()

    hosts_up = DatadogHostCache.query.join(
        DatadogIntegration
    ).filter(
        DatadogIntegration.is_active == True,
        DatadogHostCache.up == True
    ).count()

    # Get cloud provider breakdown
    cloud_counts = db.session.query(
        DatadogHostCache.cloud_provider,
        func.count(DatadogHostCache.id)
    ).join(DatadogIntegration).filter(
        DatadogIntegration.is_active == True,
        DatadogHostCache.cloud_provider.isnot(None)
    ).group_by(DatadogHostCache.cloud_provider).all()

    # Get OS breakdown
    os_counts = db.session.query(
        DatadogHostCache.platform,
        func.count(DatadogHostCache.id)
    ).join(DatadogIntegration).filter(
        DatadogIntegration.is_active == True,
        DatadogHostCache.platform.isnot(None)
    ).group_by(DatadogHostCache.platform).all()

    # Integration summaries
    integration_summaries = []
    for integration in integrations:
        host_count = DatadogHostCache.query.filter_by(
            integration_id=integration.id
        ).count()

        up_count = DatadogHostCache.query.filter_by(
            integration_id=integration.id,
            up=True
        ).count()

        integration_summaries.append({
            'id': integration.id,
            'name': integration.name,
            'host_count': host_count,
            'hosts_up': up_count,
            'hosts_down': host_count - up_count,
            'last_sync': integration.last_sync.isoformat() if integration.last_sync else None,
            'last_sync_status': integration.last_sync_status
        })

    return jsonify({
        'generated_at': datetime.utcnow().isoformat(),
        'total_hosts': total_hosts,
        'hosts_up': hosts_up,
        'hosts_down': total_hosts - hosts_up,
        'cloud_providers': {provider: count for provider, count in cloud_counts if provider},
        'platforms': {platform: count for platform, count in os_counts if platform},
        'integrations': integration_summaries
    })


@api_bp.route('/datadog/hosts/search', methods=['GET'])
@login_required
def search_datadog_hosts():
    """
    Search Datadog hosts with advanced filtering.

    Query parameters:
    - q: General search query (searches name, tags, apps)
    - os: Filter by OS (linux, windows, etc.)
    - agent_version: Filter by agent version
    - has_link: Filter by whether host is linked to Muse host (true/false)
    """
    from app.models import DatadogHostCache, DatadogIntegration

    query = DatadogHostCache.query.join(
        DatadogIntegration
    ).filter(DatadogIntegration.is_active == True)

    # General search
    q = request.args.get('q')
    if q:
        search_term = f'%{q}%'
        query = query.filter(
            db.or_(
                DatadogHostCache.host_name.ilike(search_term),
                DatadogHostCache.tags.ilike(search_term),
                DatadogHostCache.apps.ilike(search_term),
                DatadogHostCache.aliases.ilike(search_term)
            )
        )

    # OS filter
    os_filter = request.args.get('os')
    if os_filter:
        query = query.filter(
            db.or_(
                DatadogHostCache.os_name.ilike(f'%{os_filter}%'),
                DatadogHostCache.platform.ilike(f'%{os_filter}%')
            )
        )

    # Agent version filter
    agent_version = request.args.get('agent_version')
    if agent_version:
        query = query.filter(DatadogHostCache.agent_version.ilike(f'%{agent_version}%'))

    # Linked to Muse host filter
    has_link = request.args.get('has_link')
    if has_link is not None:
        if has_link.lower() in ('true', '1', 'yes'):
            query = query.filter(DatadogHostCache.muse_host_id.isnot(None))
        else:
            query = query.filter(DatadogHostCache.muse_host_id.is_(None))

    # Pagination
    page = request.args.get('page', 1, type=int)
    per_page = min(request.args.get('per_page', 50, type=int), 200)

    total = query.count()
    hosts = query.order_by(DatadogHostCache.host_name).offset(
        (page - 1) * per_page
    ).limit(per_page).all()

    return jsonify({
        'hosts': [h.to_dict() for h in hosts],
        'total': total,
        'page': page,
        'per_page': per_page,
        'query': {
            'q': q,
            'os': os_filter,
            'agent_version': agent_version,
            'has_link': has_link
        }
    })
