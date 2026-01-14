from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, SelectField, IntegerField, TextAreaField, PasswordField
from wtforms.validators import DataRequired, Optional, NumberRange
from app import db
from app.models import Host, ScanResult

main_bp = Blueprint('main', __name__)


class HostForm(FlaskForm):
    hostname = StringField('Hostname', validators=[DataRequired()])
    ip_address = StringField('IP Address', validators=[Optional()])
    os_type = SelectField('OS Type', choices=[('linux', 'Linux'), ('windows', 'Windows')])
    ssh_port = IntegerField('SSH Port', default=22, validators=[NumberRange(1, 65535)])
    winrm_port = IntegerField('WinRM Port', default=5985, validators=[NumberRange(1, 65535)])
    username = StringField('Username', validators=[Optional()])
    password = PasswordField('Password', validators=[Optional()])
    ssh_key = TextAreaField('SSH Private Key', validators=[Optional()])


@main_bp.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    return redirect(url_for('auth.login'))


@main_bp.route('/dashboard')
@login_required
def dashboard():
    hosts = Host.query.filter_by(user_id=current_user.id).all()

    # Calculate summary stats
    total_hosts = len(hosts)
    online_hosts = sum(1 for h in hosts if h.status == 'online')
    offline_hosts = sum(1 for h in hosts if h.status == 'offline')
    error_hosts = sum(1 for h in hosts if h.status == 'error')

    return render_template(
        'dashboard.html',
        hosts=hosts,
        total_hosts=total_hosts,
        online_hosts=online_hosts,
        offline_hosts=offline_hosts,
        error_hosts=error_hosts
    )


@main_bp.route('/hosts/add', methods=['GET', 'POST'])
@login_required
def add_host():
    form = HostForm()
    if form.validate_on_submit():
        host = Host(
            hostname=form.hostname.data,
            ip_address=form.ip_address.data or None,
            os_type=form.os_type.data,
            ssh_port=form.ssh_port.data,
            winrm_port=form.winrm_port.data,
            username=form.username.data or None,
            password_encrypted=form.password.data or None,
            ssh_key=form.ssh_key.data or None,
            user_id=current_user.id
        )
        db.session.add(host)
        db.session.commit()
        flash(f'Host {host.hostname} added successfully!', 'success')
        return redirect(url_for('main.dashboard'))

    return render_template('hosts/add.html', form=form)


@main_bp.route('/hosts/<int:host_id>')
@login_required
def host_detail(host_id):
    host = Host.query.filter_by(id=host_id, user_id=current_user.id).first_or_404()
    latest_scan = ScanResult.query.filter_by(host_id=host.id).order_by(ScanResult.created_at.desc()).first()
    scan_history = ScanResult.query.filter_by(host_id=host.id).order_by(ScanResult.created_at.desc()).limit(10).all()

    return render_template(
        'hosts/detail.html',
        host=host,
        latest_scan=latest_scan,
        scan_history=scan_history
    )


@main_bp.route('/hosts/<int:host_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_host(host_id):
    host = Host.query.filter_by(id=host_id, user_id=current_user.id).first_or_404()
    form = HostForm(obj=host)

    if form.validate_on_submit():
        host.hostname = form.hostname.data
        host.ip_address = form.ip_address.data or None
        host.os_type = form.os_type.data
        host.ssh_port = form.ssh_port.data
        host.winrm_port = form.winrm_port.data
        host.username = form.username.data or None
        if form.password.data:
            host.password_encrypted = form.password.data
        if form.ssh_key.data:
            host.ssh_key = form.ssh_key.data

        db.session.commit()
        flash(f'Host {host.hostname} updated successfully!', 'success')
        return redirect(url_for('main.host_detail', host_id=host.id))

    return render_template('hosts/edit.html', form=form, host=host)


@main_bp.route('/hosts/<int:host_id>/delete', methods=['POST'])
@login_required
def delete_host(host_id):
    host = Host.query.filter_by(id=host_id, user_id=current_user.id).first_or_404()
    hostname = host.hostname

    # Delete associated scan results
    ScanResult.query.filter_by(host_id=host.id).delete()
    db.session.delete(host)
    db.session.commit()

    flash(f'Host {hostname} deleted.', 'info')
    return redirect(url_for('main.dashboard'))


@main_bp.route('/hosts/<int:host_id>/scan', methods=['POST'])
@login_required
def scan_host(host_id):
    host = Host.query.filter_by(id=host_id, user_id=current_user.id).first_or_404()

    from app.scanner import RemoteScanner
    scanner = RemoteScanner(host)
    result = scanner.scan()

    if result.success:
        flash(f'Scan of {host.hostname} completed successfully!', 'success')
    else:
        flash(f'Scan of {host.hostname} failed: {result.error_message}', 'error')

    return redirect(url_for('main.host_detail', host_id=host.id))
