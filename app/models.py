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

    # Network
    network_info = db.Column(db.Text, nullable=True)

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
            'network_info': self.network_info
        }
