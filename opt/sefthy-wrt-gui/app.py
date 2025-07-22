from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, send_file
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User, Config, Version, SelectedBridge
from translations.en.messages import messages as en_messages
from translations.it.messages import messages as it_messages
from collections import deque
from datetime import datetime
from functools import wraps
from io import BytesIO
import subprocess
import netifaces
import threading
import ipaddress
import zipfile
import psutil
import json
import time
import os
import re

app = Flask(__name__,
            template_folder='app/templates',
            static_folder='app/static')
import logging
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////opt/sefthy-wrt-gui/app.db'
app.config['SECURITY_PASSWORD_HASH'] = 'pbkdf2:sha256'
app.config['SECURITY_PASSWORD_SALT'] = os.urandom(24)
db.init_app(app)

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username='admin').first()
        if user and user.check_password(request.form['password']):
            session['user_id'] = user.id
            if user.first_login:
                return redirect(url_for('change_password'))
            return redirect(url_for('index'))
        flash('Invalid credentials')
    return render_template('login.html')

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        user = User.query.get(session['user_id'])
        user.password_hash = generate_password_hash(request.form['new_password'], method='pbkdf2:sha256')
        user.first_login = False
        db.session.commit()
        return redirect(url_for('index'))
    return render_template('change_password.html', get_message=get_message)


@app.route('/')
@login_required
def index():
    uptime = subprocess.getoutput('uptimex')
    load = psutil.cpu_percent()
    cpestatus = json.loads(subprocess.getoutput('/bin/bash /opt/sefthy-wrt-config/check.sh'))
    connectorstatus = get_message( cpestatus['status'] )
    vpnstatus = cpestatus['vpn']
    
    selected_bridge = SelectedBridge.query.first()
    bridge_status = None
    if selected_bridge:
        bridge_status = get_bridge_status(selected_bridge.bridge_name)

    if session.get('language', 'en') == 'en':
        uptime = uptime.replace('giorno', 'day')
        uptime = uptime.replace('ora', 'hour')
        uptime = uptime.replace('giorni', 'days')
        uptime = uptime.replace('ore', 'hours')
        uptime = uptime.replace('minuti', 'minutes')

    config = Config.query.first()
    return render_template('index.html', 
                         uptime=uptime, 
                         load=load, 
                         bridge_status=bridge_status,
                         token=config.token,
                         connectorstatus=connectorstatus,
                         vpnstatus=vpnstatus,
                         get_message=get_message)

cpu_history = deque(maxlen=90)
ram_history = deque(maxlen=90)
timestamps = deque(maxlen=90)

def collect_metrics():
    while True:
        cpu_history.append(psutil.cpu_percent())
        ram_history.append(psutil.virtual_memory().percent)
        timestamps.append(datetime.now().strftime('%H:%M:%S'))
        time.sleep(10)

threading.Thread(target=collect_metrics, daemon=True).start()

@app.route('/metrics')
def get_metrics():
    return {
        'cpu': list(cpu_history),
        'ram': list(ram_history),
        'timestamps': list(timestamps)
    }

def get_available_bridges():
    """Get all available bridge interfaces in OpenWrt"""
    bridges = []
    
    for iface in os.listdir('/sys/class/net'):
        if iface.startswith('br-') or iface == 'br0':
            bridge_path = f'/sys/class/net/{iface}/bridge'
            if os.path.exists(bridge_path):
                try:
                    is_up = os.path.exists(f'/sys/class/net/{iface}/operstate') and \
                           open(f'/sys/class/net/{iface}/operstate').read().strip() == 'up'
                    
                    try:
                        ip = netifaces.ifaddresses(iface).get(netifaces.AF_INET, [{'addr': 'N/A'}])[0]['addr']
                    except (KeyError, IndexError):
                        ip = 'N/A'
                    
                    ports = []
                    brif_path = f'/sys/class/net/{iface}/brif'
                    if os.path.exists(brif_path):
                        ports = os.listdir(brif_path)
                    
                    bridges.append({
                        'name': iface,
                        'is_up': is_up,
                        'ip': ip,
                        'ports': ports
                    })
                except (OSError, IOError):
                    continue
    
    return sorted(bridges, key=lambda x: x['name'])

def get_bridge_status(bridge_name):
    """Get status of a specific bridge"""
    try:
        is_up = os.path.exists(f'/sys/class/net/{bridge_name}/operstate') and \
               open(f'/sys/class/net/{bridge_name}/operstate').read().strip() == 'up'
        
        try:
            ip = netifaces.ifaddresses(bridge_name).get(netifaces.AF_INET, [{'addr': 'N/A'}])[0]['addr']
        except (KeyError, IndexError):
            ip = 'N/A'
        
        ports = []
        brif_path = f'/sys/class/net/{bridge_name}/brif'
        if os.path.exists(brif_path):
            ports = os.listdir(brif_path)
        
        return {
            'name': bridge_name,
            'is_up': is_up,
            'ip': ip,
            'ports': ports
        }
    except (OSError, IOError):
        return None

def validate_ip_config(ip, netmask, gateway):
    try:
        if ip:
            ipaddress.ip_address(ip)
        if netmask:
            nm = ipaddress.ip_address(netmask)
            nm_int = int(nm)
            nm_bin = bin(nm_int)[2:]
            if '01' in nm_bin:
                return False
        if gateway:
            ipaddress.ip_address(gateway)
        return True
    except ValueError:
        return False

@app.route('/download_logs')
@login_required
def download_logs():
    memory_file = BytesIO()
    with zipfile.ZipFile(memory_file, 'w', zipfile.ZIP_DEFLATED) as zf:
        for root, dirs, files in os.walk('/opt'):
            for file in files:
                if file.endswith('.db'):
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, '/opt')
                    zf.write(file_path, arcname)
        
        for root, dirs, files in os.walk('/var/log'):
            for file in files:
                if file.startswith('sefthy'):
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, '/var/log')
                    zf.write(file_path, arcname)
        
        try:
            logread_output = subprocess.check_output(['cat /var/log/messages'], text=True)
            zf.writestr('logread.txt', logread_output)
        except subprocess.CalledProcessError:
            zf.writestr('logread.txt', 'Error getting logs')

    memory_file.seek(0)
    
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    
    return send_file(
        memory_file,
        mimetype='application/zip',
        as_attachment=True,
        download_name=f'sefthy_logs_{timestamp}.zip'
    )

@app.route('/token', methods=['GET', 'POST'])
@login_required
def token():
    config = Config.query.first()
    if request.method == 'POST':
        new_token = request.form['token'].replace(' ', '')
        if new_token != config.token:
            config.token = new_token
            db.session.commit()
            if os.path.exists('/opt/sefthy-wrt-config/.config_complete'):
                os.remove('/opt/sefthy-wrt-config/.config_complete')
        return redirect(url_for('index'))
    return render_template('token.html', token=config.token,
                           get_message=get_message)

@app.route('/network', methods=['GET', 'POST'])
@login_required
def network():
    if request.method == 'POST':
        selected_bridge_name = request.form.get('selected_bridge')
        
        if not selected_bridge_name:
            flash('Please select a bridge')
            return redirect(url_for('network'))
        
        available_bridges = get_available_bridges()
        bridge_exists = any(bridge['name'] == selected_bridge_name for bridge in available_bridges)
        
        if not bridge_exists:
            flash('Selected bridge does not exist')
            return redirect(url_for('network'))
        
        selected_bridge = SelectedBridge.query.first()
        if selected_bridge:
            selected_bridge.bridge_name = selected_bridge_name
        else:
            selected_bridge = SelectedBridge(bridge_name=selected_bridge_name)
            db.session.add(selected_bridge)
        
        db.session.commit()
        flash('Bridge selection saved successfully')
        return redirect(url_for('network'))
        
    available_bridges = get_available_bridges()
    selected_bridge = SelectedBridge.query.first()
    selected_bridge_name = selected_bridge.bridge_name if selected_bridge else None
    
    return render_template('network.html',
                         available_bridges=available_bridges,
                         selected_bridge_name=selected_bridge_name,
                         get_message=get_message)

@app.route('/api/bridge_status')
def bridge_status():
    available_bridges = get_available_bridges()
    selected_bridge = SelectedBridge.query.first()
    
    return jsonify({
        'available_bridges': available_bridges,
        'selected_bridge': selected_bridge.bridge_name if selected_bridge else None
    })

@app.route('/api/health')
def health_check():
    return jsonify({'status': 'ok'})


def is_valid_hostname(hostname):
    hostname_pattern = re.compile(
        r'^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*'
        r'([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$'
    )
    return bool(hostname_pattern.match(hostname))

def is_valid_target(target):
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return is_valid_hostname(target)

@app.route('/diagnostics')
@login_required
def diagnostics():
    return render_template('diagnostics.html', get_message=get_message)

@app.route('/api/diagnostic', methods=['POST'])
@login_required
def run_diagnostic():
    tool = request.form['tool']
    target = request.form['target']
    
    if not is_valid_target(target):
        return {'result': get_message('invalid_target')}, 400
        
    if tool == 'ping':
        cmd = ['ping', '-c', '4', target]
    elif tool == 'traceroute':
        cmd = ['traceroute', '-n', target]
    elif tool == 'iperf':
        cmd = ['/opt/sefthy-wrt-gui/speedtest']
    else:
        return {'result': get_message('invalid_tool')}, 400
    
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30
        )
        return {'result': result.stdout}
    except subprocess.TimeoutExpired:
        return {'result': get_message('command_timeout')}, 408
    except Exception as e:
        return {'result': str(e)}, 500

@app.route('/api/system_status')
def system_status():
    uptime = subprocess.getoutput('uptimex')

    if session.get('language', 'en') == 'en':
        uptime = uptime.replace('giorno', 'day')
        uptime = uptime.replace('ora', 'hour')
        uptime = uptime.replace('giorni', 'days')
        uptime = uptime.replace('ore', 'hours')
        uptime = uptime.replace('minuti', 'minutes')

    load = psutil.cpu_percent()

    cpestatus = json.loads(subprocess.getoutput('/bin/bash /opt/sefthy-wrt-config/check.sh'))
    connectorstatus = get_message( cpestatus['status'] )
    vpnstatus = cpestatus['vpn']

    return jsonify({
        'uptime': uptime,
        'load': load,
        'connectorstatus': connectorstatus,
        'vpnstatus': vpnstatus
    })


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

def init_db():
    with app.app_context():
        db.create_all()
        if not User.query.first():
            admin = User(username='admin', 
                        password_hash=generate_password_hash('Sefthy', method='pbkdf2:sha256'))
            db.session.add(admin)
            config = Config()
            db.session.add(config)

        if not Version.query.first():
            version = Version(version='1.0.0')
            db.session.add(version)

        db.session.commit()

app.config['LANGUAGES'] = {
    'en': 'English',
    'it': 'Italiano'
}

def get_message(key):
    lang = session.get('language', 'en')
    messages = en_messages if lang == 'en' else it_messages
    return messages.get(key, key)

@app.route('/set_language/<lang>')
def set_language(lang):
    if lang in app.config['LANGUAGES']:
        session['language'] = lang
    return redirect(request.referrer or url_for('index'))

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=81)