from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SelectField
from wtforms.validators import DataRequired, Email, EqualTo, Length, ValidationError, Optional
from app import db
from app.models import User, AuthSettings, DomainController

auth_bp = Blueprint('auth', __name__)


def get_auth_settings():
    """Get or create authentication settings."""
    settings = AuthSettings.query.first()
    if not settings:
        settings = AuthSettings()
        db.session.add(settings)
        db.session.commit()
    return settings


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    domain = SelectField('Domain', validators=[Optional()], choices=[])
    remember = BooleanField('Remember Me')

    def __init__(self, *args, **kwargs):
        super(LoginForm, self).__init__(*args, **kwargs)
        # Populate domain choices
        settings = get_auth_settings()
        choices = [('local', 'Local Account')]

        if settings.allow_domain_auth:
            dcs = DomainController.query.filter_by(is_active=True).order_by(
                DomainController.priority, DomainController.name
            ).all()
            for dc in dcs:
                choices.append((str(dc.id), dc.name))

        self.domain.choices = choices

        # If only domain auth is allowed, remove local option
        if settings.require_domain_auth and len(choices) > 1:
            self.domain.choices = [c for c in choices if c[0] != 'local']


class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=80)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])

    def validate_username(self, field):
        if User.query.filter_by(username=field.data).first():
            raise ValidationError('Username already exists.')

    def validate_email(self, field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('Email already registered.')


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))

    settings = get_auth_settings()
    form = LoginForm()

    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        domain_choice = form.domain.data if hasattr(form, 'domain') else 'local'

        user = None
        auth_method = None

        # Try domain authentication first if selected
        if domain_choice != 'local' and settings.allow_domain_auth:
            try:
                from app.ldap_auth import ldap_auth_service

                # Get specific DC or try all
                dc_id = int(domain_choice) if domain_choice.isdigit() else None
                dc = DomainController.query.get(dc_id) if dc_id else None
                domain_hint = dc.domain_name if dc else None

                ldap_user_info = ldap_auth_service.authenticate(username, password, domain_hint)

                if ldap_user_info:
                    user = ldap_auth_service.get_or_create_user(ldap_user_info)
                    auth_method = 'domain'

                    if not user:
                        flash('Domain authentication succeeded but user provisioning is disabled. Contact an administrator.', 'error')
                        return render_template('auth/login.html', form=form, settings=settings)
                else:
                    flash(f'Domain authentication failed: {ldap_auth_service.last_error}', 'error')
                    return render_template('auth/login.html', form=form, settings=settings)

            except ImportError:
                flash('Domain authentication is not properly configured', 'error')
                return render_template('auth/login.html', form=form, settings=settings)
            except Exception as e:
                flash(f'Domain authentication error: {str(e)}', 'error')
                return render_template('auth/login.html', form=form, settings=settings)

        # Try local authentication if domain auth not selected or not required
        elif settings.allow_local_auth and not settings.require_domain_auth:
            user = User.query.filter_by(username=username).first()

            if user:
                # Check if user is domain-only
                if user.is_domain_user and not user.password_hash:
                    flash('This account requires domain authentication. Please select your domain.', 'error')
                    return render_template('auth/login.html', form=form, settings=settings)

                if user.check_password(password):
                    auth_method = 'local'
                else:
                    user = None

        # Auto-try domain auth if local failed and domain auth is enabled
        if not user and settings.allow_domain_auth and domain_choice == 'local':
            try:
                from app.ldap_auth import ldap_auth_service

                # Check if this username looks like a domain user
                ldap_user_info = ldap_auth_service.authenticate(username, password)

                if ldap_user_info:
                    user = ldap_auth_service.get_or_create_user(ldap_user_info)
                    auth_method = 'domain'

            except Exception:
                pass  # Fall through to error message

        if user:
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            return redirect(next_page or url_for('main.dashboard'))

        flash('Invalid username or password', 'error')

    return render_template('auth/login.html', form=form, settings=settings)


@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))

    settings = get_auth_settings()

    # Check if local registration is allowed
    if settings.require_domain_auth:
        flash('Local registration is disabled. Please authenticate with your domain credentials.', 'info')
        return redirect(url_for('auth.login'))

    form = RegisterForm()
    if form.validate_on_submit():
        user = User(
            username=form.username.data,
            email=form.email.data,
            is_domain_user=False
        )
        user.set_password(form.password.data)

        # First user becomes admin
        if User.query.count() == 0:
            user.is_admin = True

        db.session.add(user)
        db.session.commit()
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('auth.login'))

    return render_template('auth/register.html', form=form, settings=settings)


@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('auth.login'))
