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
    Flask, render_template, request, redirect, url_for, session,
    send_from_directory, jsonify, abort, Response
)
from flask_session import Session
from flask_httpauth import HTTPBasicAuth
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer
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

# Easter egg variables
EASTER_EGG = False
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
            # Verify 2FA token (simplified for example)
            valid = True  # Normally verify with pyotp
            if valid:
                session['authenticated'] = True
                session['username'] = username
                log_activity(f"Login successful for {username}")
                return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/dashboard')
@auth.login_required
def dashboard():
    return render_template('dashboard.html', system_stats=get_system_stats())

# Terminal with real-time output
@app.route('/execute', methods=['POST'])
@auth.login_required
def execute():
    command = request.form.get('command')
    if command == "easter_egg":
        global EASTER_EGG
        EASTER_EGG = True
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
    global EASTER_EGG
    if EASTER_EGG:
        return render_template('easter_egg.html')
    else:
        abort(404)

# WebSocket endpoints
@socketio.on('connect')
def handle_connect():
    global thread
    if not thread.is_alive():
        thread = socketio.start_background_task(system_stats_thread)

@socketio.on('disconnect')
def handle_disconnect():
    pass

# Error handlers
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

# Easter egg template (easter_egg.html)
EASTER_EGG_HTML = """
<!DOCTYPE html>
<html>
<head><title>Easter Egg</title></head>
<body style="background: #000; color: #0f0; font-family: monospace;">
    <h1 style="text-align: center;">YOU FOUND THE EASTER EGG!</h1>
    <p>Type the magic code to unlock a surprise:</p>
    <form method="POST" action="/unlock">
        <input type="text" name="code" placeholder="Enter code" required>
        <input type="submit" value="Unlock">
    </form>
</body>
</html>
"""

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

# Main template (dashboard.html)
DASHBOARD_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Cool Remote Panel</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body { background: #1a1a1a; color: #fff; }
        .card { background: #2d2d2d; border: 1px solid #555; }
        .terminal { min-height: 300px; overflow-y: auto; }
    </style>
</head>
<body>
    <nav class="navbar navbar-dark bg-dark">
        <div class="container-fluid">
            <a class="navbar-brand" href="/">Cool Remote Panel</a>
            <div class="d-flex">
                <a href="/secret" class="btn btn-success">Secret</a>
                <a href="/logout" class="btn btn-danger">Logout</a>
            </div>
        </div>
    </nav>
    
    <div class="container mt-3">
        <div class="row">
            <!-- System Stats -->
            <div class="col-md-4">
                <div class="card">
                    <div class="card-header">System Status</div>
                    <div class="card-body">
                        <p>CPU: {{ system_stats['cpu_percent'] }}%</p>
                        <p>Memory: {{ system_stats['memory_percent'] }}%</p>
                        <p>Disk: {{ system_stats['disk_percent'] }}%</p>
                        <p>OS: {{ system_stats['os'] }}</p>
                        <p>Hostname: {{ system_stats['hostname'] }}</p>
                    </div>
                </div>
            </div>
            
            <!-- Terminal -->
            <div class="col-md-8">
                <div class="card">
                    <div class="card-header">Terminal</div>
                    <div class="card-body">
                        <div class="input-group mb-3">
                            <input type="text" id="commandInput" class="form-control" placeholder="Enter command">
                            <button class="btn btn-primary" onclick="executeCommand()">Execute</button>
                        </div>
                        <div class="terminal" id="terminalOutput"></div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.5.1/socket.io.js"></script>
    <script>
        const socket = io();
        socket.on('system_stats', data => {
            // Update stats here (implement with DOM manipulation)
        });

        function executeCommand() {
            const command = document.getElementById('commandInput').value;
            const outputDiv = document.getElementById('terminalOutput');
            outputDiv.innerHTML += `<div>Executing: ${command}</div>`;
            
            const eventSource = new EventSource(`/execute?command=${encodeURIComponent(command)}`);
            eventSource.onmessage = function(e) {
                outputDiv.innerHTML += `<div>${e.data}</div>`;
            };
            eventSource.onerror = function(err) {
                outputDiv.innerHTML += `<div style="color: red;">Error: ${err}</div>`;
            };
        }
    </script>
</body>
</html>
"""

# Login template (login.html)
LOGIN_HTML = """
<!DOCTYPE html>
<html>
<head><title>Login</title></head>
<body style="background: #000; color: #0f0; font-family: monospace;">
    <div style="max-width: 400px; margin: 100px auto; padding: 20px; background: #222; border-radius: 8px;">
        <h2>Login to Cool Panel</h2>
        <form method="POST">
            <input type="text" name="username" placeholder="Username" required style="width: 100%; padding: 8px; margin: 5px 0;">
            <input type="password" name="password" placeholder="Password" required style="width: 100%; padding: 8px; margin: 5px 0;">
            <input type="text" name="token" placeholder="2FA Token" required style="width: 100%; padding: 8px; margin: 5px 0;">
            <input type="submit" value="Login" class="btn btn-success" style="width: 100%; padding: 10px; margin-top: 10px;">
        </form>
    </div>
</body>
</html>
"""

# 404 template
FOUR_O FOUR_HTML = """
<!DOCTYPE html>
<html>
<head><title>404</title></head>
<body style="background: #000; color: #ff0; font-family: monospace;">
    <h1 style="text-align: center;">404 - Page Not Found</h1>
    <p style="text-align: center;">This page is as lost as your cat in a maze.</p>
</body>
</html>
"""

if __name__ == '__main__':
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])
    socketio.run(app, host='0.0.0.0', port=5000)
