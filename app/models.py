from datetime import datetime
from flask_login import UserMixin
from app import db
import bcrypt


class User(UserMixin, db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_admin = db.Column(db.Boolean, default=False)

    hosts = db.relationship('Host', backref='owner', lazy=True)

    def set_password(self, password):
        self.password_hash = bcrypt.hashpw(
            password.encode('utf-8'),
            bcrypt.gensalt()
        ).decode('utf-8')

    def check_password(self, password):
        return bcrypt.checkpw(
            password.encode('utf-8'),
            self.password_hash.encode('utf-8')
        )


class Host(db.Model):
    __tablename__ = 'hosts'

    id = db.Column(db.Integer, primary_key=True)
    hostname = db.Column(db.String(255), nullable=False)
    ip_address = db.Column(db.String(45), nullable=True)
    os_type = db.Column(db.String(20), default='linux')  # linux or windows
    ssh_port = db.Column(db.Integer, default=22)
    winrm_port = db.Column(db.Integer, default=5985)
    username = db.Column(db.String(80), nullable=True)
    password_encrypted = db.Column(db.Text, nullable=True)
    ssh_key = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_scan = db.Column(db.DateTime, nullable=True)
    status = db.Column(db.String(20), default='pending')  # pending, online, offline, error
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

    scans = db.relationship('ScanResult', backref='host', lazy=True, order_by='desc(ScanResult.created_at)')
    av_scans = db.relationship('AVScanResult', backref='host', lazy=True, order_by='desc(AVScanResult.created_at)')

    def to_dict(self):
        return {
            'id': self.id,
            'hostname': self.hostname,
            'ip_address': self.ip_address,
            'os_type': self.os_type,
            'status': self.status,
            'last_scan': self.last_scan.isoformat() if self.last_scan else None,
            'created_at': self.created_at.isoformat()
        }


class ScanResult(db.Model):
    __tablename__ = 'scan_results'

    id = db.Column(db.Integer, primary_key=True)
    host_id = db.Column(db.Integer, db.ForeignKey('hosts.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    success = db.Column(db.Boolean, default=False)
    error_message = db.Column(db.Text, nullable=True)

    # System metrics
    hostname_reported = db.Column(db.String(255), nullable=True)
    os_info = db.Column(db.Text, nullable=True)
    uptime = db.Column(db.String(255), nullable=True)

    # CPU & Memory
    cpu_usage = db.Column(db.Float, nullable=True)
    memory_total = db.Column(db.BigInteger, nullable=True)
    memory_used = db.Column(db.BigInteger, nullable=True)
    memory_percent = db.Column(db.Float, nullable=True)

    # Disk
    disk_info = db.Column(db.Text, nullable=True)

    # Users & Processes
    logged_users = db.Column(db.Text, nullable=True)
    running_processes = db.Column(db.Text, nullable=True)
    process_count = db.Column(db.Integer, nullable=True)

    # Logs & Events
    recent_logs = db.Column(db.Text, nullable=True)

    # Detailed Log Analysis
    security_events = db.Column(db.Text, nullable=True)      # Failed logins, auth events
    system_events = db.Column(db.Text, nullable=True)        # Service changes, shutdowns
    application_events = db.Column(db.Text, nullable=True)   # App crashes, errors
    hardware_events = db.Column(db.Text, nullable=True)      # Disk errors, hardware issues
    critical_errors = db.Column(db.Text, nullable=True)      # Critical/Error level events
    cbs_logs = db.Column(db.Text, nullable=True)             # Windows CBS logs
    recent_changes = db.Column(db.Text, nullable=True)       # Recent system changes
    event_summary = db.Column(db.Text, nullable=True)        # Summary of notable events

    # Network
    network_info = db.Column(db.Text, nullable=True)

    # System Updates & Package Info
    pending_updates = db.Column(db.Text, nullable=True)       # Available updates not yet installed
    update_history = db.Column(db.Text, nullable=True)        # Recent update/patch history
    last_update_check = db.Column(db.Text, nullable=True)     # When updates were last checked

    # Driver Information
    driver_info = db.Column(db.Text, nullable=True)           # Installed drivers and versions
    driver_updates = db.Column(db.Text, nullable=True)        # Available driver updates

    # Build & Version Info
    build_info = db.Column(db.Text, nullable=True)            # Detailed OS build info
    kernel_version = db.Column(db.String(255), nullable=True) # Kernel/NT version
    installed_packages = db.Column(db.Text, nullable=True)    # Key installed packages/features

    # System Snapshot for Comparison
    system_snapshot = db.Column(db.Text, nullable=True)       # JSON snapshot for easy comparison

    def to_dict(self):
        return {
            'id': self.id,
            'host_id': self.host_id,
            'created_at': self.created_at.isoformat(),
            'success': self.success,
            'error_message': self.error_message,
            'hostname_reported': self.hostname_reported,
            'os_info': self.os_info,
            'uptime': self.uptime,
            'cpu_usage': self.cpu_usage,
            'memory_total': self.memory_total,
            'memory_used': self.memory_used,
            'memory_percent': self.memory_percent,
            'disk_info': self.disk_info,
            'logged_users': self.logged_users,
            'running_processes': self.running_processes,
            'process_count': self.process_count,
            'recent_logs': self.recent_logs,
            'security_events': self.security_events,
            'system_events': self.system_events,
            'application_events': self.application_events,
            'hardware_events': self.hardware_events,
            'critical_errors': self.critical_errors,
            'cbs_logs': self.cbs_logs,
            'recent_changes': self.recent_changes,
            'event_summary': self.event_summary,
            'network_info': self.network_info,
            'pending_updates': self.pending_updates,
            'update_history': self.update_history,
            'last_update_check': self.last_update_check,
            'driver_info': self.driver_info,
            'driver_updates': self.driver_updates,
            'build_info': self.build_info,
            'kernel_version': self.kernel_version,
            'installed_packages': self.installed_packages,
            'system_snapshot': self.system_snapshot
        }


class AVScanResult(db.Model):
    __tablename__ = 'av_scan_results'

    id = db.Column(db.Integer, primary_key=True)
    host_id = db.Column(db.Integer, db.ForeignKey('hosts.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime, nullable=True)
    success = db.Column(db.Boolean, default=False)
    error_message = db.Column(db.Text, nullable=True)

    # Scan configuration
    scan_type = db.Column(db.String(20), default='quick')  # quick, full, custom
    paths_scanned = db.Column(db.Text, nullable=True)

    # Results
    files_scanned = db.Column(db.Integer, default=0)
    threats_found = db.Column(db.Integer, default=0)
    threat_details = db.Column(db.Text, nullable=True)
    scan_summary = db.Column(db.Text, nullable=True)

    def to_dict(self):
        return {
            'id': self.id,
            'host_id': self.host_id,
            'created_at': self.created_at.isoformat(),
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'success': self.success,
            'error_message': self.error_message,
            'scan_type': self.scan_type,
            'paths_scanned': self.paths_scanned,
            'files_scanned': self.files_scanned,
            'threats_found': self.threats_found,
            'threat_details': self.threat_details,
            'scan_summary': self.scan_summary
        }
