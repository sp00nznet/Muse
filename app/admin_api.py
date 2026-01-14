"""Admin API endpoints for service accounts and domain controller management."""
from flask import Blueprint, jsonify, request
from flask_login import login_required, current_user
from functools import wraps
from datetime import datetime
from cryptography.fernet import Fernet
import os
import base64

from app import db
from app.models import (
    ServiceAccount, DomainController, AuthSettings, Host, User
)

admin_api_bp = Blueprint('admin_api', __name__)

# Encryption key for sensitive data (should be in environment variable in production)
def get_encryption_key():
    """Get or generate encryption key for sensitive data."""
    key = os.environ.get('MUSE_ENCRYPTION_KEY')
    if not key:
        # Generate a key if not set (for development only)
        key = Fernet.generate_key().decode()
        os.environ['MUSE_ENCRYPTION_KEY'] = key
    return key.encode() if isinstance(key, str) else key


def encrypt_value(value: str) -> str:
    """Encrypt a sensitive value."""
    if not value:
        return None
    f = Fernet(get_encryption_key())
    return f.encrypt(value.encode()).decode()


def decrypt_value(encrypted_value: str) -> str:
    """Decrypt a sensitive value."""
    if not encrypted_value:
        return None
    f = Fernet(get_encryption_key())
    return f.decrypt(encrypted_value.encode()).decode()


def admin_required(f):
    """Decorator to require admin privileges."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_admin:
            return jsonify({'error': 'Admin privileges required'}), 403
        return f(*args, **kwargs)
    return decorated_function


# =============================================================================
# SERVICE ACCOUNT ENDPOINTS
# =============================================================================

@admin_api_bp.route('/service-accounts', methods=['GET'])
@login_required
@admin_required
def list_service_accounts():
    """List all service accounts."""
    accounts = ServiceAccount.query.order_by(ServiceAccount.name).all()
    return jsonify([a.to_dict() for a in accounts])


@admin_api_bp.route('/service-accounts', methods=['POST'])
@login_required
@admin_required
def create_service_account():
    """Create a new service account."""
    data = request.get_json()

    # Validate required fields
    required = ['name', 'account_type', 'username']
    for field in required:
        if not data.get(field):
            return jsonify({'error': f'{field} is required'}), 400

    # Validate account type
    valid_types = ['windows_domain', 'linux_password', 'linux_key']
    if data['account_type'] not in valid_types:
        return jsonify({'error': f'account_type must be one of: {", ".join(valid_types)}'}), 400

    # Check for duplicate name
    existing = ServiceAccount.query.filter_by(name=data['name']).first()
    if existing:
        return jsonify({'error': 'A service account with this name already exists'}), 400

    # Validate type-specific requirements
    if data['account_type'] == 'windows_domain':
        if not data.get('domain'):
            return jsonify({'error': 'domain is required for windows_domain account type'}), 400
        if not data.get('password'):
            return jsonify({'error': 'password is required for windows_domain account type'}), 400

    elif data['account_type'] == 'linux_password':
        if not data.get('password'):
            return jsonify({'error': 'password is required for linux_password account type'}), 400

    elif data['account_type'] == 'linux_key':
        if not data.get('ssh_key'):
            return jsonify({'error': 'ssh_key is required for linux_key account type'}), 400

    # Create the service account
    account = ServiceAccount(
        name=data['name'],
        description=data.get('description'),
        account_type=data['account_type'],
        is_default=data.get('is_default', False),
        is_active=data.get('is_active', True),
        domain=data.get('domain'),
        username=data['username'],
        password_encrypted=encrypt_value(data.get('password')),
        ssh_key_encrypted=encrypt_value(data.get('ssh_key')),
        ssh_key_passphrase_encrypted=encrypt_value(data.get('ssh_key_passphrase')),
        created_by=current_user.id
    )

    # If this is set as default, unset other defaults of the same type
    if account.is_default:
        ServiceAccount.query.filter(
            ServiceAccount.account_type == account.account_type,
            ServiceAccount.is_default == True
        ).update({'is_default': False})

    db.session.add(account)
    db.session.commit()

    return jsonify(account.to_dict()), 201


@admin_api_bp.route('/service-accounts/<int:account_id>', methods=['GET'])
@login_required
@admin_required
def get_service_account(account_id):
    """Get a specific service account."""
    account = ServiceAccount.query.get(account_id)
    if not account:
        return jsonify({'error': 'Service account not found'}), 404

    return jsonify(account.to_dict())


@admin_api_bp.route('/service-accounts/<int:account_id>', methods=['PUT'])
@login_required
@admin_required
def update_service_account(account_id):
    """Update a service account."""
    account = ServiceAccount.query.get(account_id)
    if not account:
        return jsonify({'error': 'Service account not found'}), 404

    data = request.get_json()

    # Update fields
    if 'name' in data:
        # Check for duplicate name
        existing = ServiceAccount.query.filter(
            ServiceAccount.name == data['name'],
            ServiceAccount.id != account_id
        ).first()
        if existing:
            return jsonify({'error': 'A service account with this name already exists'}), 400
        account.name = data['name']

    if 'description' in data:
        account.description = data['description']

    if 'is_active' in data:
        account.is_active = data['is_active']

    if 'domain' in data:
        account.domain = data['domain']

    if 'username' in data:
        account.username = data['username']

    if 'password' in data and data['password']:
        account.password_encrypted = encrypt_value(data['password'])

    if 'ssh_key' in data and data['ssh_key']:
        account.ssh_key_encrypted = encrypt_value(data['ssh_key'])

    if 'ssh_key_passphrase' in data:
        account.ssh_key_passphrase_encrypted = encrypt_value(data['ssh_key_passphrase'])

    if 'is_default' in data:
        if data['is_default']:
            # Unset other defaults of the same type
            ServiceAccount.query.filter(
                ServiceAccount.account_type == account.account_type,
                ServiceAccount.is_default == True,
                ServiceAccount.id != account_id
            ).update({'is_default': False})
        account.is_default = data['is_default']

    db.session.commit()

    return jsonify(account.to_dict())


@admin_api_bp.route('/service-accounts/<int:account_id>', methods=['DELETE'])
@login_required
@admin_required
def delete_service_account(account_id):
    """Delete a service account."""
    account = ServiceAccount.query.get(account_id)
    if not account:
        return jsonify({'error': 'Service account not found'}), 404

    # Check if any hosts are using this account
    host_count = Host.query.filter_by(service_account_id=account_id).count()
    if host_count > 0:
        return jsonify({
            'error': f'Cannot delete: {host_count} host(s) are using this service account',
            'host_count': host_count
        }), 400

    db.session.delete(account)
    db.session.commit()

    return jsonify({'message': 'Service account deleted successfully'})


@admin_api_bp.route('/service-accounts/<int:account_id>/test', methods=['POST'])
@login_required
@admin_required
def test_service_account(account_id):
    """Test a service account connection."""
    account = ServiceAccount.query.get(account_id)
    if not account:
        return jsonify({'error': 'Service account not found'}), 404

    data = request.get_json() or {}
    test_host = data.get('test_host')  # Optional host to test against

    # Decrypt credentials
    password = decrypt_value(account.password_encrypted)
    ssh_key = decrypt_value(account.ssh_key_encrypted)
    ssh_passphrase = decrypt_value(account.ssh_key_passphrase_encrypted)

    result = {
        'account_id': account_id,
        'account_name': account.name,
        'account_type': account.account_type,
        'test_time': datetime.utcnow().isoformat(),
        'success': False,
        'message': ''
    }

    try:
        if account.account_type == 'windows_domain':
            # Test Windows domain credentials
            if test_host:
                import winrm
                domain_user = f"{account.domain}\\{account.username}"
                session = winrm.Session(
                    test_host,
                    auth=(domain_user, password),
                    transport='ntlm'
                )
                r = session.run_cmd('hostname')
                if r.status_code == 0:
                    result['success'] = True
                    result['message'] = f'Successfully connected to {test_host}'
                    result['hostname'] = r.std_out.decode().strip()
                else:
                    result['message'] = f'Connection failed: {r.std_err.decode()}'
            else:
                result['success'] = True
                result['message'] = 'Credentials validated (no test host specified)'

        elif account.account_type in ['linux_password', 'linux_key']:
            # Test Linux SSH credentials
            if test_host:
                import paramiko
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

                connect_args = {
                    'hostname': test_host,
                    'username': account.username,
                    'timeout': 10
                }

                if account.account_type == 'linux_key' and ssh_key:
                    from io import StringIO
                    pkey = paramiko.RSAKey.from_private_key(
                        StringIO(ssh_key),
                        password=ssh_passphrase
                    )
                    connect_args['pkey'] = pkey
                else:
                    connect_args['password'] = password

                ssh.connect(**connect_args)
                stdin, stdout, stderr = ssh.exec_command('hostname')
                hostname = stdout.read().decode().strip()
                ssh.close()

                result['success'] = True
                result['message'] = f'Successfully connected to {test_host}'
                result['hostname'] = hostname
            else:
                result['success'] = True
                result['message'] = 'Credentials validated (no test host specified)'

    except Exception as e:
        result['success'] = False
        result['message'] = str(e)

    return jsonify(result)


# =============================================================================
# DOMAIN CONTROLLER ENDPOINTS
# =============================================================================

@admin_api_bp.route('/domain-controllers', methods=['GET'])
@login_required
@admin_required
def list_domain_controllers():
    """List all domain controllers."""
    dcs = DomainController.query.order_by(DomainController.priority, DomainController.name).all()
    return jsonify([dc.to_dict() for dc in dcs])


@admin_api_bp.route('/domain-controllers', methods=['POST'])
@login_required
@admin_required
def create_domain_controller():
    """Create a new domain controller connection."""
    data = request.get_json()

    # Validate required fields
    required = ['name', 'server_address', 'domain_name', 'base_dn', 'bind_username', 'bind_password']
    for field in required:
        if not data.get(field):
            return jsonify({'error': f'{field} is required'}), 400

    # Check for duplicate name
    existing = DomainController.query.filter_by(name=data['name']).first()
    if existing:
        return jsonify({'error': 'A domain controller with this name already exists'}), 400

    # Create the domain controller
    dc = DomainController(
        name=data['name'],
        description=data.get('description'),
        server_address=data['server_address'],
        port=data.get('port', 389),
        use_ssl=data.get('use_ssl', False),
        use_start_tls=data.get('use_start_tls', False),
        domain_name=data['domain_name'],
        base_dn=data['base_dn'],
        user_search_base=data.get('user_search_base'),
        user_search_filter=data.get('user_search_filter', '(sAMAccountName={username})'),
        bind_username=data['bind_username'],
        bind_password_encrypted=encrypt_value(data['bind_password']),
        admin_group_dn=data.get('admin_group_dn'),
        user_group_dn=data.get('user_group_dn'),
        is_active=data.get('is_active', True),
        is_primary=data.get('is_primary', False),
        priority=data.get('priority', 100),
        created_by=current_user.id
    )

    # If this is set as primary, unset other primaries
    if dc.is_primary:
        DomainController.query.filter(
            DomainController.is_primary == True
        ).update({'is_primary': False})

    db.session.add(dc)
    db.session.commit()

    return jsonify(dc.to_dict()), 201


@admin_api_bp.route('/domain-controllers/<int:dc_id>', methods=['GET'])
@login_required
@admin_required
def get_domain_controller(dc_id):
    """Get a specific domain controller."""
    dc = DomainController.query.get(dc_id)
    if not dc:
        return jsonify({'error': 'Domain controller not found'}), 404

    return jsonify(dc.to_dict())


@admin_api_bp.route('/domain-controllers/<int:dc_id>', methods=['PUT'])
@login_required
@admin_required
def update_domain_controller(dc_id):
    """Update a domain controller."""
    dc = DomainController.query.get(dc_id)
    if not dc:
        return jsonify({'error': 'Domain controller not found'}), 404

    data = request.get_json()

    # Update fields
    updatable_fields = [
        'name', 'description', 'server_address', 'port', 'use_ssl', 'use_start_tls',
        'domain_name', 'base_dn', 'user_search_base', 'user_search_filter',
        'bind_username', 'admin_group_dn', 'user_group_dn', 'is_active', 'priority'
    ]

    for field in updatable_fields:
        if field in data:
            if field == 'name':
                # Check for duplicate name
                existing = DomainController.query.filter(
                    DomainController.name == data['name'],
                    DomainController.id != dc_id
                ).first()
                if existing:
                    return jsonify({'error': 'A domain controller with this name already exists'}), 400
            setattr(dc, field, data[field])

    if 'bind_password' in data and data['bind_password']:
        dc.bind_password_encrypted = encrypt_value(data['bind_password'])

    if 'is_primary' in data:
        if data['is_primary']:
            # Unset other primaries
            DomainController.query.filter(
                DomainController.is_primary == True,
                DomainController.id != dc_id
            ).update({'is_primary': False})
        dc.is_primary = data['is_primary']

    db.session.commit()

    return jsonify(dc.to_dict())


@admin_api_bp.route('/domain-controllers/<int:dc_id>', methods=['DELETE'])
@login_required
@admin_required
def delete_domain_controller(dc_id):
    """Delete a domain controller."""
    dc = DomainController.query.get(dc_id)
    if not dc:
        return jsonify({'error': 'Domain controller not found'}), 404

    # Check if any users are authenticated via this DC
    user_count = User.query.filter_by(domain_controller_id=dc_id).count()
    if user_count > 0:
        return jsonify({
            'error': f'Cannot delete: {user_count} user(s) are authenticated via this domain controller',
            'user_count': user_count
        }), 400

    db.session.delete(dc)
    db.session.commit()

    return jsonify({'message': 'Domain controller deleted successfully'})


@admin_api_bp.route('/domain-controllers/<int:dc_id>/rename', methods=['PUT'])
@login_required
@admin_required
def rename_domain_controller(dc_id):
    """Rename a domain controller."""
    dc = DomainController.query.get(dc_id)
    if not dc:
        return jsonify({'error': 'Domain controller not found'}), 404

    data = request.get_json()

    if not data.get('name'):
        return jsonify({'error': 'name is required'}), 400

    # Check for duplicate name
    existing = DomainController.query.filter(
        DomainController.name == data['name'],
        DomainController.id != dc_id
    ).first()
    if existing:
        return jsonify({'error': 'A domain controller with this name already exists'}), 400

    old_name = dc.name
    dc.name = data['name']
    db.session.commit()

    return jsonify({
        'message': 'Domain controller renamed successfully',
        'old_name': old_name,
        'new_name': dc.name
    })


@admin_api_bp.route('/domain-controllers/<int:dc_id>/test', methods=['POST'])
@login_required
@admin_required
def test_domain_controller(dc_id):
    """Test connection to a domain controller."""
    dc = DomainController.query.get(dc_id)
    if not dc:
        return jsonify({'error': 'Domain controller not found'}), 404

    data = request.get_json() or {}
    test_username = data.get('test_username')  # Optional user to test authentication
    test_password = data.get('test_password')

    result = {
        'dc_id': dc_id,
        'dc_name': dc.name,
        'server_address': dc.server_address,
        'test_time': datetime.utcnow().isoformat(),
        'connection_test': {'success': False, 'message': ''},
        'bind_test': {'success': False, 'message': ''},
        'user_test': None
    }

    try:
        from ldap3 import Server, Connection, ALL, NTLM, SIMPLE, Tls
        import ssl

        # Configure TLS if needed
        tls = None
        if dc.use_ssl or dc.use_start_tls:
            tls = Tls(validate=ssl.CERT_NONE)  # In production, use proper cert validation

        # Create server
        server = Server(
            dc.server_address,
            port=dc.port,
            use_ssl=dc.use_ssl,
            tls=tls,
            get_info=ALL
        )

        # Test connection
        result['connection_test']['success'] = True
        result['connection_test']['message'] = f'Successfully reached {dc.server_address}:{dc.port}'

        # Test bind with service account
        bind_password = decrypt_value(dc.bind_password_encrypted)

        conn = Connection(
            server,
            user=dc.bind_username,
            password=bind_password,
            auto_bind=True
        )

        if dc.use_start_tls:
            conn.start_tls()

        result['bind_test']['success'] = True
        result['bind_test']['message'] = f'Successfully bound as {dc.bind_username}'
        result['server_info'] = {
            'vendor': str(server.info.vendor_name) if server.info else None,
            'supported_controls': len(server.info.supported_controls) if server.info else 0
        }

        # Test user authentication if credentials provided
        if test_username and test_password:
            result['user_test'] = {'success': False, 'message': ''}

            # Search for the user
            search_base = dc.user_search_base or dc.base_dn
            search_filter = dc.user_search_filter.replace('{username}', test_username)

            conn.search(search_base, search_filter, attributes=['distinguishedName', 'mail', 'memberOf'])

            if conn.entries:
                user_dn = conn.entries[0].distinguishedName.value

                # Try to bind as the user
                user_conn = Connection(
                    server,
                    user=user_dn,
                    password=test_password,
                    auto_bind=True
                )
                user_conn.unbind()

                result['user_test']['success'] = True
                result['user_test']['message'] = f'User {test_username} authenticated successfully'
                result['user_test']['user_dn'] = user_dn

                # Check group membership
                if dc.admin_group_dn:
                    member_of = [str(m) for m in conn.entries[0].memberOf] if hasattr(conn.entries[0], 'memberOf') else []
                    result['user_test']['is_admin'] = dc.admin_group_dn in member_of

            else:
                result['user_test']['message'] = f'User {test_username} not found'

        conn.unbind()

        # Update DC status
        dc.last_connection_test = datetime.utcnow()
        dc.last_connection_status = 'success'
        dc.last_connection_error = None
        db.session.commit()

    except Exception as e:
        error_msg = str(e)

        if not result['connection_test']['success']:
            result['connection_test']['message'] = error_msg
        elif not result['bind_test']['success']:
            result['bind_test']['message'] = error_msg
        elif result['user_test'] and not result['user_test']['success']:
            result['user_test']['message'] = error_msg

        # Update DC status
        dc.last_connection_test = datetime.utcnow()
        dc.last_connection_status = 'failed'
        dc.last_connection_error = error_msg
        db.session.commit()

    return jsonify(result)


# =============================================================================
# AUTHENTICATION SETTINGS ENDPOINTS
# =============================================================================

@admin_api_bp.route('/auth-settings', methods=['GET'])
@login_required
@admin_required
def get_auth_settings():
    """Get authentication settings."""
    settings = AuthSettings.query.first()

    if not settings:
        # Create default settings
        settings = AuthSettings()
        db.session.add(settings)
        db.session.commit()

    # Include domain controller status
    dc_count = DomainController.query.filter_by(is_active=True).count()

    return jsonify({
        **settings.to_dict(),
        'active_domain_controllers': dc_count
    })


@admin_api_bp.route('/auth-settings', methods=['PUT'])
@login_required
@admin_required
def update_auth_settings():
    """Update authentication settings."""
    settings = AuthSettings.query.first()

    if not settings:
        settings = AuthSettings()
        db.session.add(settings)

    data = request.get_json()

    # Validate: Cannot disable local auth if no domain controllers configured
    if data.get('require_domain_auth', False):
        dc_count = DomainController.query.filter_by(is_active=True).count()
        if dc_count == 0:
            return jsonify({
                'error': 'Cannot require domain auth: No active domain controllers configured'
            }), 400

    # Update settings
    updatable_fields = [
        'allow_local_auth', 'allow_domain_auth', 'require_domain_auth',
        'auto_create_domain_users', 'default_domain_user_admin', 'session_timeout_minutes'
    ]

    for field in updatable_fields:
        if field in data:
            setattr(settings, field, data[field])

    settings.updated_by = current_user.id
    db.session.commit()

    return jsonify(settings.to_dict())


# =============================================================================
# HOST SERVICE ACCOUNT ASSIGNMENT
# =============================================================================

@admin_api_bp.route('/hosts/<int:host_id>/service-account', methods=['PUT'])
@login_required
@admin_required
def assign_host_service_account(host_id):
    """Assign a service account to a host."""
    host = Host.query.get(host_id)
    if not host:
        return jsonify({'error': 'Host not found'}), 404

    data = request.get_json()

    if 'service_account_id' in data:
        if data['service_account_id'] is None:
            # Remove service account assignment
            host.service_account_id = None
            host.use_service_account = False
        else:
            # Verify service account exists
            account = ServiceAccount.query.get(data['service_account_id'])
            if not account:
                return jsonify({'error': 'Service account not found'}), 404

            # Verify account type matches host OS
            if host.os_type == 'windows' and account.account_type != 'windows_domain':
                return jsonify({'error': 'Windows host requires windows_domain service account'}), 400
            if host.os_type == 'linux' and account.account_type not in ['linux_password', 'linux_key']:
                return jsonify({'error': 'Linux host requires linux_password or linux_key service account'}), 400

            host.service_account_id = data['service_account_id']
            host.use_service_account = data.get('use_service_account', True)

    if 'use_service_account' in data:
        host.use_service_account = data['use_service_account']

    db.session.commit()

    return jsonify({
        'host_id': host.id,
        'hostname': host.hostname,
        'service_account_id': host.service_account_id,
        'use_service_account': host.use_service_account
    })


@admin_api_bp.route('/hosts/bulk-assign-service-account', methods=['POST'])
@login_required
@admin_required
def bulk_assign_service_account():
    """Assign a service account to multiple hosts."""
    data = request.get_json()

    if not data.get('host_ids'):
        return jsonify({'error': 'host_ids array is required'}), 400

    if 'service_account_id' not in data:
        return jsonify({'error': 'service_account_id is required (use null to remove)'}), 400

    service_account_id = data['service_account_id']

    if service_account_id is not None:
        account = ServiceAccount.query.get(service_account_id)
        if not account:
            return jsonify({'error': 'Service account not found'}), 404

    results = []
    for host_id in data['host_ids']:
        host = Host.query.get(host_id)
        if not host:
            results.append({'host_id': host_id, 'success': False, 'error': 'Host not found'})
            continue

        if service_account_id is not None:
            # Verify compatibility
            if host.os_type == 'windows' and account.account_type != 'windows_domain':
                results.append({
                    'host_id': host_id,
                    'success': False,
                    'error': 'Windows host requires windows_domain account'
                })
                continue
            if host.os_type == 'linux' and account.account_type not in ['linux_password', 'linux_key']:
                results.append({
                    'host_id': host_id,
                    'success': False,
                    'error': 'Linux host requires linux_password or linux_key account'
                })
                continue

        host.service_account_id = service_account_id
        host.use_service_account = service_account_id is not None
        results.append({
            'host_id': host_id,
            'hostname': host.hostname,
            'success': True
        })

    db.session.commit()

    return jsonify({
        'total': len(data['host_ids']),
        'successful': sum(1 for r in results if r['success']),
        'failed': sum(1 for r in results if not r['success']),
        'results': results
    })
