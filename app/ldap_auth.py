"""LDAP/Active Directory authentication service."""
from datetime import datetime
from cryptography.fernet import Fernet
import os

from app import db
from app.models import DomainController, User, AuthSettings


def get_encryption_key():
    """Get encryption key for decrypting passwords."""
    key = os.environ.get('MUSE_ENCRYPTION_KEY')
    if not key:
        key = Fernet.generate_key().decode()
        os.environ['MUSE_ENCRYPTION_KEY'] = key
    return key.encode() if isinstance(key, str) else key


def decrypt_value(encrypted_value: str) -> str:
    """Decrypt a sensitive value."""
    if not encrypted_value:
        return None
    f = Fernet(get_encryption_key())
    return f.decrypt(encrypted_value.encode()).decode()


class LDAPAuthService:
    """Service for authenticating users against Active Directory/LDAP."""

    def __init__(self):
        self.last_error = None

    def get_active_domain_controllers(self):
        """Get list of active domain controllers ordered by priority."""
        return DomainController.query.filter_by(
            is_active=True
        ).order_by(
            DomainController.priority,
            DomainController.is_primary.desc()
        ).all()

    def authenticate(self, username: str, password: str, domain_hint: str = None):
        """
        Authenticate a user against configured domain controllers.

        Args:
            username: The username (sAMAccountName or UPN)
            password: The user's password
            domain_hint: Optional domain name to limit search

        Returns:
            dict with user info if successful, None if failed
        """
        self.last_error = None

        # Get domain controllers to try
        dcs = self.get_active_domain_controllers()

        if not dcs:
            self.last_error = "No active domain controllers configured"
            return None

        # If domain hint provided, filter DCs
        if domain_hint:
            dcs = [dc for dc in dcs if dc.domain_name.lower() == domain_hint.lower()]
            if not dcs:
                self.last_error = f"No domain controller found for domain: {domain_hint}"
                return None

        # Try each DC in order
        for dc in dcs:
            result = self._authenticate_against_dc(dc, username, password)
            if result:
                return result

        return None

    def _authenticate_against_dc(self, dc: DomainController, username: str, password: str):
        """
        Attempt to authenticate against a specific domain controller.

        Returns:
            dict with user info if successful, None if failed
        """
        try:
            from ldap3 import Server, Connection, ALL, Tls, SUBTREE
            import ssl

            # Configure TLS
            tls = None
            if dc.use_ssl or dc.use_start_tls:
                tls = Tls(validate=ssl.CERT_NONE)  # Use proper cert validation in production

            # Create server
            server = Server(
                dc.server_address,
                port=dc.port,
                use_ssl=dc.use_ssl,
                tls=tls,
                get_info=ALL
            )

            # First, bind with service account to search for user
            bind_password = decrypt_value(dc.bind_password_encrypted)
            service_conn = Connection(
                server,
                user=dc.bind_username,
                password=bind_password,
                auto_bind=True
            )

            if dc.use_start_tls and not dc.use_ssl:
                service_conn.start_tls()

            # Search for the user
            search_base = dc.user_search_base or dc.base_dn
            search_filter = dc.user_search_filter.replace('{username}', username)

            service_conn.search(
                search_base,
                search_filter,
                search_scope=SUBTREE,
                attributes=['distinguishedName', 'sAMAccountName', 'mail', 'displayName', 'memberOf', 'userPrincipalName']
            )

            if not service_conn.entries:
                service_conn.unbind()
                self.last_error = f"User '{username}' not found in {dc.domain_name}"
                return None

            user_entry = service_conn.entries[0]
            user_dn = str(user_entry.distinguishedName)

            # Extract user attributes
            user_info = {
                'dn': user_dn,
                'username': str(user_entry.sAMAccountName) if hasattr(user_entry, 'sAMAccountName') else username,
                'email': str(user_entry.mail) if hasattr(user_entry, 'mail') and user_entry.mail else f"{username}@{dc.domain_name}",
                'display_name': str(user_entry.displayName) if hasattr(user_entry, 'displayName') else username,
                'upn': str(user_entry.userPrincipalName) if hasattr(user_entry, 'userPrincipalName') else None,
                'member_of': [str(m) for m in user_entry.memberOf] if hasattr(user_entry, 'memberOf') else [],
                'domain_controller_id': dc.id,
                'domain_name': dc.domain_name
            }

            service_conn.unbind()

            # Now try to bind as the user to verify password
            user_conn = Connection(
                server,
                user=user_dn,
                password=password
            )

            if not user_conn.bind():
                self.last_error = f"Invalid password for user '{username}'"
                return None

            user_conn.unbind()

            # Check group membership for access control
            user_info['is_admin'] = False
            user_info['has_access'] = True

            if dc.admin_group_dn:
                user_info['is_admin'] = dc.admin_group_dn.lower() in [m.lower() for m in user_info['member_of']]

            if dc.user_group_dn:
                # If a user group is specified, check membership
                user_info['has_access'] = dc.user_group_dn.lower() in [m.lower() for m in user_info['member_of']]
                # Admins always have access
                if user_info['is_admin']:
                    user_info['has_access'] = True

            if not user_info['has_access']:
                self.last_error = f"User '{username}' is not a member of the required access group"
                return None

            # Update DC connection status
            dc.last_connection_test = datetime.utcnow()
            dc.last_connection_status = 'success'
            dc.last_connection_error = None
            db.session.commit()

            return user_info

        except Exception as e:
            self.last_error = str(e)

            # Update DC connection status
            dc.last_connection_test = datetime.utcnow()
            dc.last_connection_status = 'failed'
            dc.last_connection_error = str(e)
            db.session.commit()

            return None

    def get_or_create_user(self, ldap_user_info: dict) -> User:
        """
        Get or create a local user record for a domain-authenticated user.

        Args:
            ldap_user_info: User info dict from authenticate()

        Returns:
            User object
        """
        settings = AuthSettings.query.first()
        if not settings:
            settings = AuthSettings()
            db.session.add(settings)
            db.session.commit()

        # Look for existing user by domain username
        user = User.query.filter_by(
            domain_username=ldap_user_info['username'],
            domain_controller_id=ldap_user_info['domain_controller_id']
        ).first()

        if user:
            # Update user info from AD
            user.email = ldap_user_info['email']
            user.domain_user_dn = ldap_user_info['dn']
            user.last_domain_sync = datetime.utcnow()

            # Update admin status if controlled by AD group
            dc = DomainController.query.get(ldap_user_info['domain_controller_id'])
            if dc and dc.admin_group_dn:
                user.is_admin = ldap_user_info['is_admin']

            db.session.commit()
            return user

        # Also check by username (legacy or local)
        user = User.query.filter_by(username=ldap_user_info['username']).first()

        if user:
            # Convert existing local user to domain user
            user.is_domain_user = True
            user.domain_controller_id = ldap_user_info['domain_controller_id']
            user.domain_username = ldap_user_info['username']
            user.domain_user_dn = ldap_user_info['dn']
            user.email = ldap_user_info['email']
            user.last_domain_sync = datetime.utcnow()

            dc = DomainController.query.get(ldap_user_info['domain_controller_id'])
            if dc and dc.admin_group_dn:
                user.is_admin = ldap_user_info['is_admin']

            db.session.commit()
            return user

        # Create new user if auto-provisioning is enabled
        if not settings.auto_create_domain_users:
            return None

        user = User(
            username=ldap_user_info['username'],
            email=ldap_user_info['email'],
            is_domain_user=True,
            domain_controller_id=ldap_user_info['domain_controller_id'],
            domain_username=ldap_user_info['username'],
            domain_user_dn=ldap_user_info['dn'],
            last_domain_sync=datetime.utcnow(),
            is_admin=ldap_user_info['is_admin'] if settings.default_domain_user_admin else ldap_user_info.get('is_admin', False)
        )

        db.session.add(user)
        db.session.commit()

        return user


# Singleton instance
ldap_auth_service = LDAPAuthService()
