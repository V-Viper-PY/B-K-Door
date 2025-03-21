import os
import sys
import subprocess
import socket
import json
import base64
import uuid
import random
import string
from datetime import datetime
from flask import (
    Flask, render_template_string, request, redirect, url_for, session,
    send_from_directory, jsonify, abort, Response
)
from flask_session import Session
from flask_httpauth import HTTPBasicAuth
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename  # Added missing import
from flask_socketio import SocketIO, emit
from threading import Thread, Event
import psutil
import platform

# Configuration
app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SESSION_TYPE'] = 'filesystem'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max upload
Session(app)
socketio = SocketIO(app, async_mode='threading')
auth = HTTPBasicAuth()

# Database (in-memory for simplicity)
USERS = {
    "admin": {
        "password": generate_password_hash("your_secure_password"),
        "2fa_secret": "JBSWY3DPEHPK3PXP",
        "role": "admin"
    }
}
LOG_FILE = "activity.log"

# Easter egg variables (now session-based)
EASTER_EGG_CODE = "42"

# System monitoring
def get_system_stats():
    return {
        "cpu_percent": psutil.cpu_percent(),
        "memory_percent": psutil.virtual_memory().percent,
        "disk_percent": psutil.disk_usage('/').percent,
        "os": platform.system(),
        "hostname": socket.gethostname()
    }

# Logging function
def log_activity(message):
    with open(LOG_FILE, 'a') as f:
        f.write(f"[{datetime.now()}] {message}\n")

# SocketIO thread for real-time updates
thread = Thread()
thread_stop_event = Event()

def system_stats_thread():
    while not thread_stop_event.is_set():
        socketio.sleep(2)
        socketio.emit('system_stats', get_system_stats())

# Authentication
@auth.verify_password
def verify_password(username, password):
    if username in USERS and check_password_hash(USERS[username]['password'], password):
        return username

# Routes
@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if session.get('authenticated'):
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        token = request.form.get('token')
        if username in USERS and check_password_hash(USERS[username]['password'], password):
            # Basic 2FA simulation (replace with pyotp for real use)
            valid = token == "123456"  # Example token
            if valid:
                session['authenticated'] = True
                session['username'] = username
                log_activity(f"Login successful for {username}")
                return redirect(url_for('dashboard'))
    return render_template_string(LOGIN_HTML)  # Use string rendering

# Terminal with real-time output
@app.route('/execute', methods=['GET', 'POST'])  # Now accepts GET for SSE
@auth.login_required
def execute():
    if request.method == 'POST':
        command = request.form.get('command')
    else:
        command = request.args.get('command')  # For SSE requests
    
    if command == "easter_egg":
        session['easter_egg_activated'] = True  # Session-based activation
        return jsonify({"output": "Easter egg activated!"})
    
    try:
        def generate():
            process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            while True:
                output = process.stdout.readline()
                if not output and process.poll() is not None:
                    break
                if output:
                    yield f"data: {output.decode('utf-8')}"
        return Response(generate(), mimetype='text/event-stream')
    except Exception as e:
        return jsonify({"error": str(e)})

# File Manager
@app.route('/upload', methods=['POST'])
@auth.login_required
def upload():
    file = request.files['file']
    if file:
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        log_activity(f"Uploaded file: {filename}")
    return redirect(url_for('dashboard'))

@app.route('/download/<path:filename>')
@auth.login_required
def download(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# Easter egg route
@app.route('/secret')
@auth.login_required
def secret():
    if session.get('easter_egg_activated'):
        return render_template_string(EASTER_EGG_HTML)
    else:
        abort(404)

# WebSocket endpoints
@socketio.on('connect')
def handle_connect():
    global thread
    if not thread.is_alive():
        thread = socketio.start_background_task(system_stats_thread)

# Unlock route
@app.route('/unlock', methods=['POST'])
@auth.login_required
def unlock():
    code = request.form.get('code')
    if code == EASTER_EGG_CODE:
        return render_template_string(f"""
        <h1 style="color: #ff0; text-align: center;">CONGRATULATIONS!</h1>
        <p>You've unlocked the secret message:</p>
        <pre style="background: #333; padding: 20px;">
        🚀🚀🚀 You're the ultimate hacker! 🚀🚀🚀
        </pre>
        """)
    else:
        return redirect(url_for('secret'))

# Main template (dashboard.html) - now using string rendering
DASHBOARD_HTML = """
... [Same as before but using render_template_string] ...
"""

# Login template (login.html) - fixed form enctype
LOGIN_HTML = """
<!DOCTYPE html>
<html>
<head><title>Login</title></head>
<body style="background: #000; color: #0f0; font-family: monospace;">
    <div style="max-width: 400px; margin: 100px auto; padding: 20px; background: #222; border-radius: 8px;">
        <h2>Login to Cool Panel</h2>
        <form method="POST" enctype="multipart/form-data">
            <input type="text" name="username" placeholder="Username" required style="width: 100%; padding: 8px; margin: 5px 0;">
            <input type="password" name="password" placeholder="Password" required style="width: 100%; padding: 8px; margin: 5px 0;">
            <input type="text" name="token" placeholder="2FA Token" required style="width: 100%; padding: 8px; margin: 5px 0;">
            <input type="submit" value="Login" style="width: 100%; padding: 10px; margin-top: 10px;">
        </form>
    </div>
</body>
</html>
"""

# 404 template (fixed variable name)
FOUR_O_FOUR_HTML = """
<!DOCTYPE html>
<html>
<head><title>404</title></head>
body style="background: #000; color: #ff0; font-family: monospace;">
    <h1 style="text-align: center;">404 - Page Not Found</h1>
    <p style="text-align: center;">This page is as lost as your cat in a maze.</p>
</body>
</html>
"""

@app.errorhandler(404)
def page_not_found(e):
    return render_template_string(FOUR_O_FOUR_HTML), 404

if __name__ == '__main__':
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])
    socketio.run(app, host='0.0.0.0', port=5000)
