from flask import Blueprint, jsonify, request
from flask_login import login_required, current_user
from app import db
from app.models import Host, ScanResult, AVScanResult
from app.scanner import RemoteScanner
from app.av_scanner import ClamAVScanner

api_bp = Blueprint('api', __name__)


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
