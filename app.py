from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from sqlalchemy import text
from datetime import datetime
import re
import os
import time
import proxmoxer
import secrets
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, SelectField
from wtforms.validators import DataRequired, Length, EqualTo

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(16)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    public_key = db.Column(db.Text)
    is_admin = db.Column(db.Boolean, default=False)
    vms = db.relationship('VM', backref='owner', lazy=True)
    vm_requests = db.relationship('VMRequest', backref='requester', foreign_keys='VMRequest.user_id', lazy=True)

class VM(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    vmid = db.Column(db.Integer)
    name = db.Column(db.String(50), nullable=False)
    type = db.Column(db.String(10), nullable=False)
    ip = db.Column(db.String(45))
    ssh_user = db.Column(db.String(20))
    ssh_password = db.Column(db.String(50))
    upid = db.Column(db.Text)
    provision_log = db.Column(db.Text)
    provisioned = db.Column(db.Boolean, default=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref='vms_owned', foreign_keys=[user_id])


class VMRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    vm_type = db.Column(db.String(10), nullable=False)
    message = db.Column(db.Text)
    status = db.Column(db.String(20), default='pending')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    admin_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    response_message = db.Column(db.Text)
    vm_id = db.Column(db.Integer, db.ForeignKey('vm.id'))
    admin = db.relationship('User', foreign_keys=[admin_id])
    vm = db.relationship('VM', foreign_keys=[vm_id])

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    public_key = TextAreaField('Public SSH Key (optional)')
    submit = SubmitField('Sign Up')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class VMForm(FlaskForm):
    vm_type = StringField('VM Type', validators=[DataRequired()])
    submit = SubmitField('Create VM')


class RequestVMForm(FlaskForm):
    vm_type = SelectField('VM Type', choices=[('bronze','Bronze'), ('silver','Silver'), ('gold','Gold')], validators=[DataRequired()])
    message = TextAreaField('Message (optional)')
    submit = SubmitField('Request VM')

@app.route('/')
@login_required
def home():
    # Redirect admin users to admin area; regular users see their VMs/requests
    if _is_admin_user(current_user):
        return redirect(url_for('admin_requests'))
    vms = VM.query.filter_by(user_id=current_user.id).all()
    requests = VMRequest.query.filter_by(user_id=current_user.id).order_by(VMRequest.created_at.desc()).all()
    return render_template('home.html', vms=vms, requests=requests)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data, password=form.password.data, public_key=(form.public_key.data or None))
        db.session.add(user)
        db.session.commit()
        flash('Account created!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and user.password == form.password.data:
            login_user(user)
            return redirect(url_for('home'))
        else:
            flash('Login unsuccessful. Please check email and password', 'danger')
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/create_vm', methods=['GET', 'POST'])
@login_required
def create_vm():
    # only admins may directly create/provision VMs
    if not (current_user.is_authenticated and (getattr(current_user, 'is_admin', False) or current_user.username == 'admin')):
        flash('You must be an admin to create VMs directly. Submit a request instead.', 'warning')
        return redirect(url_for('request_vm'))

    form = VMForm()
    if form.validate_on_submit():
        vm_type = form.vm_type.data.lower()
        if vm_type not in ['bronze', 'silver', 'gold']:
            flash('Invalid VM type', 'danger')
            return redirect(url_for('create_vm'))

        default_ssh_password = os.getenv('DEFAULT_SSH_PASSWORD', 'Password&1')
        proxmox = _create_proxmox_client()

        raw_name = f"{current_user.username}-{vm_type}-{secrets.token_hex(4)}"
        hostname = re.sub(r'[^a-z0-9-]', '-', raw_name.lower()).strip('-')[:63]

        node_name = _get_node_name()
        node = proxmox.nodes(node_name)
        storage_name = os.getenv('PROXMOX_STORAGE', 'local-lvm')
        templates = {
            'bronze': {'template_vmid': 2210, 'memory': 512, 'cores': 1, 'storage': storage_name},
            'silver': {'template_vmid': 2220, 'memory': 1024, 'cores': 2, 'storage': storage_name},
            'gold': {'template_vmid': 2230, 'memory': 2048, 'cores': 2, 'storage': storage_name}
        }
        config = templates[vm_type]

        try:
            nextid = proxmox.cluster.nextid.get()
            vmid = int(nextid)
        except Exception:
            flash('Unable to obtain next VMID from Proxmox cluster', 'danger')
            return redirect(url_for('create_vm'))

        try:
            clone_resp = proxmox.nodes('px1').lxc(config['template_vmid']).clone.post(
                newid=vmid,
                hostname=hostname,
                storage=config['storage'],
                full=1
            )
            app.logger.info('clone returned: %s', repr(clone_resp))
            proxmox.nodes('px1').lxc(vmid).config.post(memory=config['memory'], cores=config['cores'])
            proxmox.nodes('px1').lxc(vmid).status.start.post()
            flash(f'Provisioning started (vmid={vmid}).', 'info')
            upid = None  # clone API may not return upid consistently
        except proxmoxer.core.ResourceException as e:
            app.logger.error('Proxmox clone failed: %s', str(e))
            flash(f'Proxmox error: {e}', 'danger')
            return redirect(url_for('create_vm'))

        created = False
        container_info = None
        for i in range(60):
            try:
                container_info = proxmox.nodes(node_name).lxc(vmid).status.current.get()
                app.logger.info('Container %s status at poll %s: %s', vmid, i, repr(container_info))
                created = True
                break
            except Exception as e:
                app.logger.debug('Container %s not yet present (poll %s): %s', vmid, i, e)
                time.sleep(1)

        ip = None
        if created:
            try:
                if isinstance(container_info, dict):
                    for v in container_info.values():
                        if isinstance(v, str) and 'ip=' in v:
                            m = re.search(r'ip=([^,\s/]+)', v)
                            if m:
                                cand = m.group(1)
                                if cand.lower() != 'dhcp':
                                    ip = cand
                                    break
                if not ip:
                    conf = proxmox.nodes(node_name).lxc(vmid).config.get()
                    for val in conf.values():
                        if isinstance(val, str) and 'ip=' in val:
                            m = re.search(r'ip=([^,\s/]+)', val)
                            if m:
                                cand = m.group(1)
                                if cand.lower() != 'dhcp':
                                    ip = cand
                                    break
                # if still no ip, try agent (if available)
                if not ip:
                    try:
                        agent = proxmox.nodes(node_name).lxc(vmid).agent.get()
                        app.logger.debug('Agent info for %s: %s', vmid, repr(agent))
                        if isinstance(agent, dict):
                            for val in agent.values():
                                if isinstance(val, str) and re.search(r'\b\d{1,3}(?:\.\d{1,3}){3}\b', val):
                                    m = re.search(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b', val)
                                    if m:
                                        ip = m.group(1)
                                        break
                    except Exception as e:
                        app.logger.debug('Agent query failed for %s: %s', vmid, e)
            except Exception:
                ip = None

        if created and current_user.public_key:
            try:
                cmd = ["/bin/sh", "-lc", f"mkdir -p /root/.ssh && echo \"{current_user.public_key}\" >> /root/.ssh/authorized_keys && chmod 600 /root/.ssh/authorized_keys"]
                proxmox.nodes(node_name).lxc(vmid).exec.post(command=cmd)
            except Exception:
                flash('VM created but failed to automatically install SSH public key; add it manually.', 'warning')

        if created:
            _set_root_password(proxmox, node_name, vmid, default_ssh_password)
            ip = _refresh_ip_and_enable_ssh(proxmox, node_name, vmid) or ip

        vm = VM(name=hostname, type=vm_type, ip=_clean_ip(ip), ssh_user='root', ssh_password=default_ssh_password, user_id=current_user.id, vmid=vmid, upid=None, provision_log=None, provisioned=bool(created))
        db.session.add(vm)
        db.session.commit()
        flash('VM created successfully!', 'success')
        return redirect(url_for('home'))

    return render_template('create_vm.html', form=form)


@app.route('/request_vm', methods=['GET', 'POST'])
@login_required
def request_vm():
    # admins should not submit requests
    if _is_admin_user(current_user):
        flash('Admins cannot submit VM requests.', 'warning')
        return redirect(url_for('admin_requests'))

    form = RequestVMForm()
    if form.validate_on_submit():
        vmr = VMRequest(vm_type=form.vm_type.data.lower(), message=(form.message.data or None), user_id=current_user.id)
        db.session.add(vmr)
        db.session.commit()
        flash('VM request submitted and pending admin approval.', 'info')
        return redirect(url_for('home'))
    return render_template('request_vm.html', form=form)


@app.route('/vm/<int:vm_id>/refresh_ip', methods=['POST'])
@login_required
def refresh_vm_ip(vm_id):
    """Manually refresh VM IP and ensure SSH is up."""
    vm = VM.query.get_or_404(vm_id)
    if not (_is_admin_user(current_user) or vm.user_id == current_user.id):
        flash('Access denied', 'danger')
        return redirect(url_for('home'))
    if not vm.vmid:
        flash('VMID non presente; provisioning non completato.', 'warning')
        return redirect(url_for('home'))

    proxmox = _create_proxmox_client()
    node_name = _get_node_name()
    try:
        ip = _refresh_ip_and_enable_ssh(proxmox, node_name, vm.vmid)
        new_ip = _clean_ip(ip)
        if new_ip:
            vm.ip = new_ip
            db.session.commit()
            flash(f'IP aggiornato: {new_ip} (SSH avviato).', 'success')
        else:
            db.session.commit()
            flash('SSH avviato, ma nessun IP trovato. Verifica rete o DHCP del template.', 'warning')
    except Exception as e:
        app.logger.exception('Refresh IP failed for vm %s', vm_id)
        flash(f'Impossibile aggiornare IP: {e}', 'danger')
    return redirect(url_for('home'))


def _is_admin_user(user):
    return user.is_authenticated and (user.is_admin or user.username == 'admin')


def _get_node_name():
    return os.getenv('PROXMOX_NODE', 'px1')


def _create_proxmox_client():
    """Build a ProxmoxAPI client supporting either password or API token auth."""
    proxmox_host = os.getenv('PROXMOX_HOST', '192.168.56.15')
    proxmox_user = os.getenv('PROXMOX_USER', 'root@pam')
    proxmox_pass = os.getenv('PROXMOX_PASS', 'Password&1')
    proxmox_token_name = os.getenv('PROXMOX_TOKEN_NAME')
    proxmox_token_value = os.getenv('PROXMOX_TOKEN_VALUE')
    proxmox_timeout = int(os.getenv('PROXMOX_TIMEOUT', '15'))

    client_kwargs = {
        'user': proxmox_user,
        'verify_ssl': False,
        'timeout': proxmox_timeout,
    }
    # Prefer token auth if both pieces are provided
    if proxmox_token_name and proxmox_token_value:
        client_kwargs['token_name'] = proxmox_token_name
        client_kwargs['token_value'] = proxmox_token_value
    else:
        client_kwargs['password'] = proxmox_pass

    return proxmoxer.ProxmoxAPI(proxmox_host, **client_kwargs)


def _set_root_password(proxmox, node_name, vmid, password):
    try:
        proxmox.nodes(node_name).lxc(vmid).config.put(password=password)
    except Exception as e:
        app.logger.warning("Failed to set root password for %s: %s", vmid, e)


def _discover_ip(proxmox, node_name, vmid):
    """Try multiple ways to get the IP of a started container."""
    ip = None
    # quick call: hostname -I
    try:
        res = proxmox.nodes(node_name).lxc(vmid).exec.post(command=["hostname", "-I"])
        data = res.get('data') if isinstance(res, dict) else res
        if isinstance(data, list):
            data = " ".join([str(x) for x in data])
        if isinstance(data, str):
            m = re.search(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b', data)
            if m:
                return m.group(1)
    except Exception:
        pass

    try:
        status = proxmox.nodes(node_name).lxc(vmid).status.current.get()
        if isinstance(status, dict):
            for v in status.values():
                if isinstance(v, str) and 'ip=' in v:
                    m = re.search(r'ip=([^,\s/]+)', v)
                    if m:
                        cand = m.group(1)
                        if cand.lower() != 'dhcp':
                            return cand
    except Exception:
        pass

    try:
        conf = proxmox.nodes(node_name).lxc(vmid).config.get()
        # try to extract ip from net0/net1 lines
        if isinstance(conf, dict):
            iface_names = []
            for key, val in conf.items():
                if isinstance(val, str) and 'ip=' in val:
                    m = re.search(r'ip=([^,\s/]+)', val)
                    if m:
                        cand = m.group(1)
                        if cand.lower() != 'dhcp':
                            return cand
                if key.startswith('net') and isinstance(val, str):
                    mname = re.search(r'name=([^, ]+)', val)
                    if mname:
                        iface_names.append(mname.group(1))
            if not iface_names:
                iface_names = ['eth0', 'eth1']
            for iface in iface_names:
                try:
                    res = proxmox.nodes(node_name).lxc(vmid).exec.post(command=["ip", "-4", "-o", "addr", "show", "dev", iface])
                    data = res.get('data') if isinstance(res, dict) else res
                    if isinstance(data, list):
                        data = "\n".join([str(x) for x in data])
                    if isinstance(data, str):
                        m = re.search(r'\b(\d{1,3}(?:\.\d{1,3}){3})\/', data)
                        if m:
                            return m.group(1)
                except Exception:
                    continue
    except Exception:
        pass

    # last resort: any interface
    try:
        res = proxmox.nodes(node_name).lxc(vmid).exec.post(command=["ip", "-4", "-o", "addr", "show"])
        data = res.get('data') if isinstance(res, dict) else res
        if isinstance(data, list):
            data = "\n".join([str(x) for x in data])
        if isinstance(data, str):
            m = re.search(r'\b(\d{1,3}(?:\.\d{1,3}){3})\/', data)
            if m:
                return m.group(1)
    except Exception as e:
        app.logger.debug("ip addr any-if failed for %s: %s", vmid, e)
    return ip


def _wait_for_ip(proxmox, node_name, vmid, attempts=30, delay=2):
    ip = None
    for _ in range(attempts):
        ip = _discover_ip(proxmox, node_name, vmid)
        if ip:
            break
        time.sleep(delay)
    return ip


def _clean_ip(ip):
    """Normalize unusable placeholders (e.g., dhcp)."""
    if not ip:
        return None
    if isinstance(ip, str) and ip.strip().lower() == 'dhcp':
        return None
    return ip


def _run_exec_text(proxmox, node_name, vmid, cmd):
    """
    Run a command via LXC exec and return stdout as text (best effort).
    """
    try:
        res = proxmox.nodes(node_name).lxc(vmid).exec.post(command=cmd)
    except Exception:
        return ""
    # proxmoxer may return dict with 'data', or with 'stdout'/other keys
    if isinstance(res, dict):
        if 'data' in res:
            data = res['data']
        elif 'stdout' in res:
            data = res['stdout']
        elif 'result' in res:
            data = res['result']
        else:
            data = res
    else:
        data = res
    if isinstance(data, bytes):
        return data.decode(errors='ignore')
    if isinstance(data, list):
        return "\n".join([str(x) for x in data])
    return str(data)


def _fetch_ip_via_exec(proxmox, node_name, vmid):
    """
    Try to read an IP from inside the container (no Agent required).
    Returns first non-loopback IPv4 if found.
    """
    def _to_text(data):
        if isinstance(data, bytes):
            return data.decode(errors='ignore')
        if isinstance(data, list):
            return "\n".join([_to_text(x) for x in data])
        return str(data)

    commands = [
        "ip -4 -o addr show dev eth0",
        "ip -4 addr show dev eth0",
        "ip -4 -o addr show",
        "ip -4 addr show",
        "hostname -I",
        "ip -4 -o addr show dev eth1",
        "ip -4 addr show dev eth1",
    ]
    for shell_cmd in commands:
        text = _run_exec_text(proxmox, node_name, vmid, ["/bin/sh", "-c", shell_cmd])
        if not text:
            continue
        # regex all IPv4s
        m = re.findall(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b', text)
        for cand in m:
            if not cand.startswith('127.'):
                return cand
        # fallback: parse lines containing "inet "
        for line in text.splitlines():
            if 'inet ' in line:
                parts = line.strip().split()
                for idx, part in enumerate(parts):
                    if part == 'inet' and idx + 1 < len(parts):
                        addr = parts[idx + 1].split('/')[0]
                        if re.match(r'\d{1,3}(?:\.\d{1,3}){3}', addr) and not addr.startswith('127.'):
                            return addr
    return None


def _refresh_ip_and_enable_ssh(proxmox, node_name, vmid):
    """
    Best-effort: start/enable ssh and fetch IP from inside the container.
    """
    _ensure_ssh_running(proxmox, node_name, vmid)
    # small wait to let network settle
    time.sleep(2)
    ip = _wait_for_ip(proxmox, node_name, vmid, attempts=20, delay=2)
    if not ip:
        ip = _fetch_ip_via_exec(proxmox, node_name, vmid)
    return _clean_ip(ip)


def _ensure_ssh_running(proxmox, node_name, vmid):
    """Best effort: start/enable ssh, install if missing."""
    cmds = [
        ["systemctl", "start", "ssh"],
        ["systemctl", "enable", "ssh"],
        ["service", "ssh", "start"],
        ["service", "sshd", "start"],
        ["rc-service", "sshd", "start"],
        ["rc-update", "add", "sshd", "default"],
        ["/etc/init.d/ssh", "start"],
        ["/etc/init.d/sshd", "start"],
        ["update-rc.d", "ssh", "enable"],
    ]
    for cmd in cmds:
        try:
            proxmox.nodes(node_name).lxc(vmid).exec.post(command=cmd)
        except Exception:
            continue
    # try install openssh-server if still missing (Debian/Ubuntu)
    try:
        proxmox.nodes(node_name).lxc(vmid).exec.post(command=["apt-get", "update"])
        proxmox.nodes(node_name).lxc(vmid).exec.post(command=["apt-get", "install", "-y", "openssh-server"])
        proxmox.nodes(node_name).lxc(vmid).exec.post(command=["systemctl", "enable", "--now", "ssh"])
        return
    except Exception as e:
        app.logger.debug("ssh install/start may have failed (apt) for %s: %s", vmid, e)
    # try Alpine apk
    try:
        proxmox.nodes(node_name).lxc(vmid).exec.post(command=["apk", "add", "--no-cache", "openssh"])
        proxmox.nodes(node_name).lxc(vmid).exec.post(command=["rc-update", "add", "sshd", "default"])
        proxmox.nodes(node_name).lxc(vmid).exec.post(command=["rc-service", "sshd", "start"])
    except Exception as e:
        app.logger.debug("ssh install/start may have failed (apk) for %s: %s", vmid, e)
    # last resort: direct start
    try:
        proxmox.nodes(node_name).lxc(vmid).exec.post(command=["/etc/init.d/ssh", "start"])
    except Exception:
        pass

@app.route('/admin/requests')
@login_required
def admin_requests():
    if not _is_admin_user(current_user):
        flash('Admin access required', 'danger')
        return redirect(url_for('home'))
    reqs = VMRequest.query.order_by(VMRequest.created_at.desc()).all()
    return render_template('admin_requests.html', requests=reqs)


@app.route('/admin/request/<int:request_id>/reject', methods=['POST'])
@login_required
def admin_reject_request(request_id):
    if not _is_admin_user(current_user):
        flash('Admin access required', 'danger')
        return redirect(url_for('home'))
    vmr = VMRequest.query.get_or_404(request_id)
    resp = request.form.get('response')
    vmr.status = 'rejected'
    vmr.admin_id = current_user.id
    vmr.response_message = resp
    db.session.commit()
    flash('Request rejected.', 'info')
    return redirect(url_for('admin_requests'))


@app.route('/admin/request/<int:request_id>/approve', methods=['POST'])
@login_required
def admin_approve_request(request_id):
    if not _is_admin_user(current_user):
        flash('Admin access required', 'danger')
        return redirect(url_for('home'))
    vmr = VMRequest.query.get_or_404(request_id)
    resp = request.form.get('response')
    # attempt to provision the VM for the requesting user
    target_user = User.query.get(vmr.user_id)
    if not target_user:
        vmr.status = 'failed'
        vmr.admin_id = current_user.id
        vmr.response_message = 'Target user not found.'
        db.session.commit()
        flash('Target user not found; request marked failed.', 'danger')
        return redirect(url_for('admin_requests'))

    default_ssh_password = os.getenv('DEFAULT_SSH_PASSWORD', 'Password&1')
    proxmox = _create_proxmox_client()
    node_name = _get_node_name()
    node = proxmox.nodes(node_name)
    storage_name = os.getenv('PROXMOX_STORAGE', 'local-lvm')
    templates = {
        'bronze': {'template_vmid': 2210, 'memory': 512, 'cores': 1, 'storage': storage_name},
        'silver': {'template_vmid': 2220, 'memory': 1024, 'cores': 2, 'storage': storage_name},
        'gold': {'template_vmid': 2230, 'memory': 2048, 'cores': 2, 'storage': storage_name}
    }
    config = templates.get(vmr.vm_type, templates['bronze'])

    # prepare hostname for the requesting user
    raw_name = f"{target_user.username}-{vmr.vm_type}-{secrets.token_hex(4)}"
    hostname = re.sub(r'[^a-z0-9-]', '-', raw_name.lower()).strip('-')[:63]

    try:
        nextid = proxmox.cluster.nextid.get()
        vmid = int(nextid)
    except Exception as e:
        vmr.status = 'failed'
        vmr.admin_id = current_user.id
        vmr.response_message = f'Failed to get vmid: {e}'
        db.session.commit()
        flash('Failed to obtain VMID from Proxmox; see logs.', 'danger')
        return redirect(url_for('admin_requests'))

    upid = None
    last_task_log = None
    try:
        clone_resp = node.lxc(config['template_vmid']).clone.post(
            newid=vmid,
            hostname=hostname,
            storage=config['storage'],
            full=1
        )
        app.logger.info('Admin clone returned: %s', repr(clone_resp))
        if isinstance(clone_resp, str) and clone_resp.startswith('UPID'):
            upid = clone_resp
        elif isinstance(clone_resp, dict):
            upid = clone_resp.get('upid') or clone_resp.get('UPID')
    except Exception as e:
        vmr.status = 'failed'
        vmr.admin_id = current_user.id
        vmr.response_message = f'Proxmox clone failed: {e}'
        db.session.commit()
        app.logger.exception('Proxmox clone failed')
        flash('Proxmox clone failed; request marked failed.', 'danger')
        return redirect(url_for('admin_requests'))

    # wait for clone task to finish
    if upid:
        for i in range(120):
            try:
                status = proxmox.cluster.tasks(upid).status.get()
                app.logger.debug('Clone task %s status (%s): %s', upid, i, status)
                try:
                    tlog = proxmox.cluster.tasks(upid).log.get()
                    last_task_log = repr(tlog)
                except Exception:
                    pass
                if status.get('status') == 'stopped':
                    if status.get('exitstatus') not in (None, 'OK', '0'):
                        vmr.status = 'failed'
                        vmr.admin_id = current_user.id
                        vmr.response_message = f'Proxmox clone failed: {status}'
                        db.session.commit()
                        flash('Proxmox task failed; request marked failed.', 'danger')
                        return redirect(url_for('admin_requests'))
                    break
            except Exception as e:
                app.logger.debug('Error polling clone task %s: %s', upid, e)
            time.sleep(1)
    else:
        # if no upid returned, small wait to let CT appear
        time.sleep(3)

    # apply config and start container
    try:
        proxmox.nodes(node_name).lxc(vmid).config.put(memory=config['memory'], cores=config['cores'])
        proxmox.nodes(node_name).lxc(vmid).status.start.post()
    except Exception as e:
        vmr.status = 'failed'
        vmr.admin_id = current_user.id
        vmr.response_message = f'Proxmox config/start failed: {e}'
        db.session.commit()
        app.logger.exception('Proxmox config/start failed')
        flash('Proxmox config/start failed; request marked failed.', 'danger')
        return redirect(url_for('admin_requests'))

    # poll for container and try to get IP
    created = False
    container_info = None
    for i in range(60):
        try:
            container_info = proxmox.nodes(node_name).lxc(vmid).status.current.get()
            app.logger.info('Container %s status at poll %s: %s', vmid, i, repr(container_info))
            created = True
            break
        except Exception as e:
            app.logger.debug('Container %s not yet present (poll %s): %s', vmid, i, e)
            time.sleep(1)

    ip = None
    if created:
        try:
            if isinstance(container_info, dict):
                for v in container_info.values():
                    if isinstance(v, str) and 'ip=' in v:
                        m = re.search(r'ip=([^,\s/]+)', v)
                        if m:
                            ip = m.group(1)
                            break
            if not ip:
                conf = proxmox.nodes(node_name).lxc(vmid).config.get()
                for val in conf.values():
                    if isinstance(val, str) and 'ip=' in val:
                        m = re.search(r'ip=([^,\s/]+)', val)
                        if m:
                            ip = m.group(1)
                            break
            if not ip:
                try:
                    agent = proxmox.nodes(node_name).lxc(vmid).agent.get()
                    app.logger.debug('Agent info for %s: %s', vmid, repr(agent))
                    if isinstance(agent, dict):
                        for val in agent.values():
                            if isinstance(val, str) and re.search(r'\b\d{1,3}(?:\.\d{1,3}){3}\b', val):
                                m = re.search(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b', val)
                                if m:
                                    ip = m.group(1)
                                    break
                except Exception as e:
                    app.logger.debug('Agent query failed for %s: %s', vmid, e)
        except Exception:
            ip = None

    # try to inject user's public key if present
    if created and target_user.public_key:
        try:
            cmd = ["/bin/sh", "-lc", f"mkdir -p /root/.ssh && echo \"{target_user.public_key}\" >> /root/.ssh/authorized_keys && chmod 600 /root/.ssh/authorized_keys"]
            proxmox.nodes(node_name).lxc(vmid).exec.post(command=cmd)
        except Exception:
            app.logger.exception('Failed to install public key')

    # create VM DB record for the requesting user
    if created:
        _set_root_password(proxmox, node_name, vmid, default_ssh_password)
        ip = _refresh_ip_and_enable_ssh(proxmox, node_name, vmid) or ip

    vm = VM(
        name=hostname,
        type=vmr.vm_type,
        ip=_clean_ip(ip),
        ssh_user='root',
        ssh_password=default_ssh_password,
        user_id=target_user.id,
        vmid=vmid,
        upid=upid,
        provision_log=(last_task_log or None),
        provisioned=bool(created),
    )
    db.session.add(vm)
    db.session.flush()  # get vm.id without committing yet so we can link request

    vmr.status = 'approved' if created else 'failed'
    vmr.admin_id = current_user.id
    vmr.vm_id = vm.id  # link request to the provisioned VM so users can see credentials
    vmr.response_message = resp or ('Provisioned' if created else 'Provision failed')
    db.session.commit()
    flash('Request processed: ' + vmr.status, 'info')
    return redirect(url_for('admin_requests'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        try:
            result = db.session.execute(text("PRAGMA table_info('user')"))
            cols = [row[1] for row in result]
            if 'public_key' not in cols:
                db.session.execute(text("ALTER TABLE user ADD COLUMN public_key TEXT"))
                db.session.commit()
        except Exception:
            pass
        try:
            result = db.session.execute(text("PRAGMA table_info('vm')"))
            cols = [row[1] for row in result]
            if 'vmid' not in cols:
                db.session.execute(text("ALTER TABLE vm ADD COLUMN vmid INTEGER"))
            if 'upid' not in cols:
                db.session.execute(text("ALTER TABLE vm ADD COLUMN upid TEXT"))
            if 'provision_log' not in cols:
                db.session.execute(text("ALTER TABLE vm ADD COLUMN provision_log TEXT"))
            if 'provisioned' not in cols:
                db.session.execute(text("ALTER TABLE vm ADD COLUMN provisioned INTEGER DEFAULT 0"))
            db.session.commit()
        except Exception:
            pass
        # ensure `is_admin` exists on user table
        try:
            result = db.session.execute(text("PRAGMA table_info('user')"))
            cols = [row[1] for row in result]
            if 'is_admin' not in cols:
                db.session.execute(text("ALTER TABLE user ADD COLUMN is_admin INTEGER DEFAULT 0"))
                db.session.commit()
        except Exception:
            pass
        # ensure default admin user exists
        try:
            admin_user = User.query.filter_by(username='admin').first()
            if not admin_user:
                admin_user = User(username='admin', email='admin@example.com', password='adminpass', is_admin=True)
                db.session.add(admin_user)
                db.session.commit()
                app.logger.info('Default admin user created: admin/adminpass')
        except Exception:
            pass
        # ensure vm_id exists on vm_request table (link to provisioned VM)
        try:
            result = db.session.execute(text("PRAGMA table_info('vm_request')"))
            cols = [row[1] for row in result]
            if 'vm_id' not in cols:
                db.session.execute(text("ALTER TABLE vm_request ADD COLUMN vm_id INTEGER"))
                db.session.commit()
        except Exception:
            pass
        # cleanup old/invalid VMRequest rows: keep only pending/approved/rejected
        try:
            valid = ('pending','approved','rejected')
            bad = VMRequest.query.filter(~VMRequest.status.in_(valid)).all()
            for b in bad:
                db.session.delete(b)
            db.session.commit()
            app.logger.info('Cleaned up %s invalid VMRequest rows', len(bad))
        except Exception:
            pass
    app.run(debug=True)
if __name__ == '__main__':
    with app.app_context():
        # Create tables (if missing)
        db.create_all()
        # Ensure `public_key` column exists in `user` table (lightweight migration)
        try:
            result = db.session.execute(text("PRAGMA table_info('user')"))
            cols = [row[1] for row in result]
            if 'public_key' not in cols:
                db.session.execute(text("ALTER TABLE user ADD COLUMN public_key TEXT"))
                db.session.commit()
        except Exception:
            # If migration fails, continue; users can recreate DB manually
            pass
    app.run(debug=True)