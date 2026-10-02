# Module: Flask Application Backend & Authentication Controller
import os
import secrets
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify

import database as db
import crypto_utils as crypto
from security import (
    is_ip_locked,
    record_failed_attempt,
    reset_failed_attempts,
    get_or_create_csrf_token,
    require_csrf,
    login_required,
    apply_security_headers
)

app = Flask(__name__, static_folder='src', template_folder='templates')
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))

# Session cookie security settings
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=False  # Set True in production with HTTPS
)

# Apply security headers on every response
@app.after_request
def after_request_security(response):
    return apply_security_headers(response)

# Inject CSRF token into Jinja2 templates context
@app.context_processor
def inject_csrf_token():
    return dict(csrf_token=get_or_create_csrf_token())

# Root route: redirect to dashboard or login
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

# User Registration endpoint
@app.route('/register', methods=['GET', 'POST'])
@require_csrf
def register():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        master_password = request.form.get('master_password', '')
        confirm_password = request.form.get('confirm_password', '')

        if not username or not master_password:
            flash('Username and master password are required.', 'danger')
            return render_template('register.html')

        if len(master_password) < 10:
            flash('Master password must be at least 10 characters long.', 'warning')
            return render_template('register.html')

        if master_password != confirm_password:
            flash('Master passwords do not match.', 'danger')
            return render_template('register.html')

        # Check if username is taken
        if db.get_user_by_username(username):
            flash('Username already exists. Please select another.', 'danger')
            return render_template('register.html')

        # Generate salt & compute master hash
        salt = crypto.generate_salt()
        master_hash = crypto.hash_master_password(master_password, salt)

        if db.create_user(username, master_hash, salt):
            flash('Registration successful! Please login with your master password.', 'success')
            return redirect(url_for('login'))
        else:
            flash('An error occurred during account creation. Try again.', 'danger')

    return render_template('register.html')

# User Login endpoint with rate limiting
@app.route('/login', methods=['GET', 'POST'])
@require_csrf
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))

    client_ip = request.remote_addr or '127.0.0.1'
    is_locked, remaining = is_ip_locked(client_ip)

    if is_locked:
        flash(f'Account locked due to consecutive failed attempts. Retry in {remaining}s.', 'danger')
        return render_template('login.html', locked=True, remaining=remaining), 429

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        master_password = request.form.get('master_password', '')

        user = db.get_user_by_username(username)
        if user:
            salt = user['salt']
            expected_hash = user['master_hash']

            # Constant-time verification
            if crypto.verify_master_password(master_password, salt, expected_hash):
                reset_failed_attempts(client_ip)
                session.clear()
                session['user_id'] = user['id']
                session['username'] = user['username']
                
                # Derive session encryption key in memory for vault operations
                session_key = crypto.derive_key(master_password, salt)
                session['vault_key'] = session_key.decode('utf-8')
                
                flash(f'Welcome back, {user["username"]}!', 'success')
                return redirect(url_for('dashboard'))

        # Record failed attempt upon bad credentials
        record_failed_attempt(client_ip)
        is_locked_now, remaining_now = is_ip_locked(client_ip)
        if is_locked_now:
            flash(f'Too many failed attempts. Locked out for {remaining_now} seconds.', 'danger')
            return render_template('login.html', locked=True, remaining=remaining_now), 429
        else:
            flash('Invalid username or master password.', 'danger')

    return render_template('login.html', locked=False)

# User Logout endpoint
@app.route('/logout')
def logout():
    session.clear()
    flash('You have been securely logged out.', 'success')
    return redirect(url_for('login'))

# Placeholder dashboard route (CRUD endpoints in Commit 5)
@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', entries=[])

if __name__ == '__main__':
    db.init_db()
    app.run(host='127.0.0.1', port=5000, debug=True)
