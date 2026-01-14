from datetime import datetime
from flask_login import UserMixin
from app import db
import bcrypt


class User(UserMixin, db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=True)  # Nullable for domain-only users
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_admin = db.Column(db.Boolean, default=False)

    # Domain authentication fields
    is_domain_user = db.Column(db.Boolean, default=False)  # User authenticates via domain
    domain_controller_id = db.Column(db.Integer, db.ForeignKey('domain_controllers.id'), nullable=True)
    domain_username = db.Column(db.String(255), nullable=True)  # sAMAccountName or UPN
    domain_user_dn = db.Column(db.String(500), nullable=True)  # Full DN from LDAP
    last_domain_sync = db.Column(db.DateTime, nullable=True)  # Last time user info synced from AD

    hosts = db.relationship('Host', backref='owner', lazy=True)

    def set_password(self, password):
        self.password_hash = bcrypt.hashpw(
            password.encode('utf-8'),
            bcrypt.gensalt()
        ).decode('utf-8')

    def check_password(self, password):
        if not self.password_hash:
            return False
        return bcrypt.checkpw(
            password.encode('utf-8'),
            self.password_hash.encode('utf-8')
        )

    def is_local_user(self):
        """Check if user can authenticate locally."""
        return not self.is_domain_user and self.password_hash is not None


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

    # Service account for authentication (optional - overrides host-level credentials)
    service_account_id = db.Column(db.Integer, db.ForeignKey('service_accounts.id'), nullable=True)
    use_service_account = db.Column(db.Boolean, default=False)  # Use service account instead of host creds

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
            'created_at': self.created_at.isoformat(),
            'service_account_id': self.service_account_id,
            'use_service_account': self.use_service_account
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


class ServiceAccount(db.Model):
    """Service accounts used to connect to remote hosts."""
    __tablename__ = 'service_accounts'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    description = db.Column(db.Text, nullable=True)
    account_type = db.Column(db.String(20), nullable=False)  # windows_domain, linux_password, linux_key
    is_default = db.Column(db.Boolean, default=False)
    is_active = db.Column(db.Boolean, default=True)

    # Windows Domain Credentials
    domain = db.Column(db.String(255), nullable=True)  # e.g., CONTOSO.COM

    # Common fields
    username = db.Column(db.String(255), nullable=False)
    password_encrypted = db.Column(db.Text, nullable=True)

    # Linux SSH Key
    ssh_key_encrypted = db.Column(db.Text, nullable=True)
    ssh_key_passphrase_encrypted = db.Column(db.Text, nullable=True)

    # Audit fields
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)

    # Relationships
    hosts = db.relationship('Host', backref='service_account', lazy=True)

    def to_dict(self, include_sensitive=False):
        data = {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'account_type': self.account_type,
            'is_default': self.is_default,
            'is_active': self.is_active,
            'domain': self.domain,
            'username': self.username,
            'has_password': bool(self.password_encrypted),
            'has_ssh_key': bool(self.ssh_key_encrypted),
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'host_count': len(self.hosts)
        }
        return data


class DomainController(db.Model):
    """Domain controllers for LDAP/AD user authentication."""
    __tablename__ = 'domain_controllers'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)  # Friendly name
    description = db.Column(db.Text, nullable=True)

    # Connection settings
    server_address = db.Column(db.String(255), nullable=False)  # IP or hostname
    port = db.Column(db.Integer, default=389)  # 389 for LDAP, 636 for LDAPS
    use_ssl = db.Column(db.Boolean, default=False)  # Use LDAPS
    use_start_tls = db.Column(db.Boolean, default=False)  # Use StartTLS

    # Domain settings
    domain_name = db.Column(db.String(255), nullable=False)  # e.g., contoso.com
    base_dn = db.Column(db.String(500), nullable=False)  # e.g., DC=contoso,DC=com
    user_search_base = db.Column(db.String(500), nullable=True)  # e.g., OU=Users,DC=contoso,DC=com
    user_search_filter = db.Column(db.String(500), default='(sAMAccountName={username})')

    # Bind credentials (service account for LDAP queries)
    bind_username = db.Column(db.String(255), nullable=False)  # e.g., svc_muse@contoso.com
    bind_password_encrypted = db.Column(db.Text, nullable=False)

    # Group mapping (optional - for role-based access)
    admin_group_dn = db.Column(db.String(500), nullable=True)  # DN of group that gets admin rights
    user_group_dn = db.Column(db.String(500), nullable=True)  # DN of group allowed to access

    # Status
    is_active = db.Column(db.Boolean, default=True)  # Is this DC used for authentication
    is_primary = db.Column(db.Boolean, default=False)  # Primary DC (fallback order)
    priority = db.Column(db.Integer, default=100)  # Lower = higher priority

    # Connection status
    last_connection_test = db.Column(db.DateTime, nullable=True)
    last_connection_status = db.Column(db.String(20), nullable=True)  # success, failed
    last_connection_error = db.Column(db.Text, nullable=True)

    # Audit fields
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)

    def to_dict(self, include_sensitive=False):
        data = {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'server_address': self.server_address,
            'port': self.port,
            'use_ssl': self.use_ssl,
            'use_start_tls': self.use_start_tls,
            'domain_name': self.domain_name,
            'base_dn': self.base_dn,
            'user_search_base': self.user_search_base,
            'user_search_filter': self.user_search_filter,
            'bind_username': self.bind_username,
            'admin_group_dn': self.admin_group_dn,
            'user_group_dn': self.user_group_dn,
            'is_active': self.is_active,
            'is_primary': self.is_primary,
            'priority': self.priority,
            'last_connection_test': self.last_connection_test.isoformat() if self.last_connection_test else None,
            'last_connection_status': self.last_connection_status,
            'last_connection_error': self.last_connection_error,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }
        return data


class AuthSettings(db.Model):
    """Global authentication settings."""
    __tablename__ = 'auth_settings'

    id = db.Column(db.Integer, primary_key=True)

    # Authentication modes
    allow_local_auth = db.Column(db.Boolean, default=True)  # Allow local username/password
    allow_domain_auth = db.Column(db.Boolean, default=False)  # Allow AD/LDAP authentication
    require_domain_auth = db.Column(db.Boolean, default=False)  # Require domain auth (disable local)

    # Auto-provisioning for domain users
    auto_create_domain_users = db.Column(db.Boolean, default=True)  # Create user on first domain login
    default_domain_user_admin = db.Column(db.Boolean, default=False)  # New domain users are admins

    # Session settings
    session_timeout_minutes = db.Column(db.Integer, default=480)  # 8 hours default

    # Audit
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    updated_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)

    def to_dict(self):
        return {
            'id': self.id,
            'allow_local_auth': self.allow_local_auth,
            'allow_domain_auth': self.allow_domain_auth,
            'require_domain_auth': self.require_domain_auth,
            'auto_create_domain_users': self.auto_create_domain_users,
            'default_domain_user_admin': self.default_domain_user_admin,
            'session_timeout_minutes': self.session_timeout_minutes,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }


class DatadogIntegration(db.Model):
    """Datadog integration settings for pulling host information."""
    __tablename__ = 'datadog_integrations'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)  # Friendly name
    description = db.Column(db.Text, nullable=True)

    # API Configuration
    api_key_encrypted = db.Column(db.Text, nullable=False)
    app_key_encrypted = db.Column(db.Text, nullable=False)
    site = db.Column(db.String(50), default='datadoghq.com')  # datadoghq.com, datadoghq.eu, us3.datadoghq.com, etc.

    # Sync settings
    is_active = db.Column(db.Boolean, default=True)
    sync_interval_minutes = db.Column(db.Integer, default=15)  # How often to pull data
    last_sync = db.Column(db.DateTime, nullable=True)
    last_sync_status = db.Column(db.String(20), nullable=True)  # success, failed
    last_sync_error = db.Column(db.Text, nullable=True)
    last_sync_host_count = db.Column(db.Integer, nullable=True)

    # Filter settings (optional)
    filter_tags = db.Column(db.Text, nullable=True)  # JSON array of tags to filter hosts
    filter_query = db.Column(db.Text, nullable=True)  # Datadog host query filter

    # Display settings
    show_metrics = db.Column(db.Boolean, default=True)  # Show CPU, memory metrics
    show_tags = db.Column(db.Boolean, default=True)  # Show host tags
    show_integrations = db.Column(db.Boolean, default=True)  # Show installed integrations

    # Audit fields
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)

    def to_dict(self, include_sensitive=False):
        data = {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'site': self.site,
            'is_active': self.is_active,
            'sync_interval_minutes': self.sync_interval_minutes,
            'last_sync': self.last_sync.isoformat() if self.last_sync else None,
            'last_sync_status': self.last_sync_status,
            'last_sync_error': self.last_sync_error,
            'last_sync_host_count': self.last_sync_host_count,
            'filter_tags': self.filter_tags,
            'filter_query': self.filter_query,
            'show_metrics': self.show_metrics,
            'show_tags': self.show_tags,
            'show_integrations': self.show_integrations,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'has_api_key': bool(self.api_key_encrypted),
            'has_app_key': bool(self.app_key_encrypted)
        }
        return data


class DatadogHostCache(db.Model):
    """Cached host information from Datadog."""
    __tablename__ = 'datadog_host_cache'

    id = db.Column(db.Integer, primary_key=True)
    integration_id = db.Column(db.Integer, db.ForeignKey('datadog_integrations.id'), nullable=False)

    # Host identification
    datadog_host_id = db.Column(db.String(255), nullable=False)  # Unique ID from Datadog
    host_name = db.Column(db.String(255), nullable=False)
    aliases = db.Column(db.Text, nullable=True)  # JSON array of aliases

    # Host info
    up = db.Column(db.Boolean, default=True)  # Is host reporting
    last_reported = db.Column(db.DateTime, nullable=True)
    os_name = db.Column(db.String(100), nullable=True)
    platform = db.Column(db.String(100), nullable=True)

    # Metrics
    cpu_cores = db.Column(db.Integer, nullable=True)
    cpu_usage = db.Column(db.Float, nullable=True)
    memory_total = db.Column(db.BigInteger, nullable=True)
    memory_usage = db.Column(db.Float, nullable=True)
    load_avg = db.Column(db.Float, nullable=True)

    # Cloud info
    cloud_provider = db.Column(db.String(50), nullable=True)  # aws, azure, gcp
    cloud_instance_type = db.Column(db.String(100), nullable=True)
    cloud_instance_id = db.Column(db.String(255), nullable=True)
    cloud_region = db.Column(db.String(100), nullable=True)
    cloud_availability_zone = db.Column(db.String(100), nullable=True)

    # Tags and metadata
    tags = db.Column(db.Text, nullable=True)  # JSON array of tags
    sources = db.Column(db.Text, nullable=True)  # JSON array of reporting sources
    apps = db.Column(db.Text, nullable=True)  # JSON array of installed integrations
    meta = db.Column(db.Text, nullable=True)  # Full metadata JSON

    # Agent info
    agent_version = db.Column(db.String(50), nullable=True)
    agent_checks = db.Column(db.Text, nullable=True)  # JSON array of running checks

    # Cache management
    cached_at = db.Column(db.DateTime, default=datetime.utcnow)
    raw_data = db.Column(db.Text, nullable=True)  # Full raw JSON from Datadog

    # Link to Muse host (optional)
    muse_host_id = db.Column(db.Integer, db.ForeignKey('hosts.id'), nullable=True)

    # Unique constraint
    __table_args__ = (
        db.UniqueConstraint('integration_id', 'datadog_host_id', name='uix_dd_host'),
    )

    def to_dict(self):
        import json
        return {
            'id': self.id,
            'integration_id': self.integration_id,
            'datadog_host_id': self.datadog_host_id,
            'host_name': self.host_name,
            'aliases': json.loads(self.aliases) if self.aliases else [],
            'up': self.up,
            'last_reported': self.last_reported.isoformat() if self.last_reported else None,
            'os_name': self.os_name,
            'platform': self.platform,
            'cpu_cores': self.cpu_cores,
            'cpu_usage': self.cpu_usage,
            'memory_total': self.memory_total,
            'memory_usage': self.memory_usage,
            'load_avg': self.load_avg,
            'cloud_provider': self.cloud_provider,
            'cloud_instance_type': self.cloud_instance_type,
            'cloud_instance_id': self.cloud_instance_id,
            'cloud_region': self.cloud_region,
            'cloud_availability_zone': self.cloud_availability_zone,
            'tags': json.loads(self.tags) if self.tags else [],
            'sources': json.loads(self.sources) if self.sources else [],
            'apps': json.loads(self.apps) if self.apps else [],
            'agent_version': self.agent_version,
            'cached_at': self.cached_at.isoformat() if self.cached_at else None,
            'muse_host_id': self.muse_host_id
        }
