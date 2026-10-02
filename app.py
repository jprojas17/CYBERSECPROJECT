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

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=False
)

@app.after_request
def after_request_security(response):
    return apply_security_headers(response)

@app.context_processor
def inject_csrf_token():
    return dict(csrf_token=get_or_create_csrf_token())

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

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

        if db.get_user_by_username(username):
            flash('Username already exists. Please choose another.', 'danger')
            return render_template('register.html')

        salt = crypto.generate_salt()
        master_hash = crypto.hash_master_password(master_password, salt)

        if db.create_user(username, master_hash, salt):
            flash('Account created successfully! Please sign in.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Error creating account. Please try again.', 'danger')

    return render_template('register.html')

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

            if crypto.verify_master_password(master_password, salt, expected_hash):
                reset_failed_attempts(client_ip)
                session.clear()
                session['user_id'] = user['id']
                session['username'] = user['username']
                
                session_key = crypto.derive_key(master_password, salt)
                session['vault_key'] = session_key.decode('utf-8')
                
                flash(f'Welcome back, {user["username"]}!', 'success')
                return redirect(url_for('dashboard'))

        record_failed_attempt(client_ip)
        is_locked_now, remaining_now = is_ip_locked(client_ip)
        if is_locked_now:
            flash(f'Too many failed attempts. Locked out for {remaining_now} seconds.', 'danger')
            return render_template('login.html', locked=True, remaining=remaining_now), 429
        else:
            flash('Invalid username or master password.', 'danger')

    return render_template('login.html', locked=False)

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    user_id = session['user_id']
    entries = db.get_vault_entries_by_user(user_id)
    return render_template('dashboard.html', entries=entries)

@app.route('/vault/add', methods=['POST'])
@login_required
@require_csrf
def add_entry():
    user_id = session['user_id']
    vault_key = session.get('vault_key')

    if not vault_key:
        flash('Session expired. Please sign in again.', 'danger')
        return redirect(url_for('login'))

    service_name = request.form.get('service_name', '').strip()
    username_email = request.form.get('username_email', '').strip()
    plaintext_password = request.form.get('password', '')
    notes = request.form.get('notes', '').strip()

    if not service_name or not username_email or not plaintext_password:
        flash('Service, Account/Email and Password are required.', 'danger')
        return redirect(url_for('dashboard'))

    encrypted_pw = crypto.encrypt_credential(plaintext_password, vault_key.encode('utf-8'))
    db.add_vault_entry(user_id, service_name, username_email, encrypted_pw, notes)

    flash(f'Credential for "{service_name}" saved securely.', 'success')
    return redirect(url_for('dashboard'))

@app.route('/vault/edit/<int:entry_id>', methods=['POST'])
@login_required
@require_csrf
def edit_entry(entry_id):
    user_id = session['user_id']
    vault_key = session.get('vault_key')

    existing_entry = db.get_vault_entry_by_id(entry_id, user_id)
    if not existing_entry:
        flash('Entry not found or unauthorized.', 'danger')
        return redirect(url_for('dashboard'))

    service_name = request.form.get('service_name', '').strip()
    username_email = request.form.get('username_email', '').strip()
    plaintext_password = request.form.get('password', '')
    notes = request.form.get('notes', '').strip()

    if not service_name or not username_email:
        flash('Service and Account/Email cannot be empty.', 'danger')
        return redirect(url_for('dashboard'))

    if plaintext_password:
        encrypted_pw = crypto.encrypt_credential(plaintext_password, vault_key.encode('utf-8'))
    else:
        encrypted_pw = existing_entry['encrypted_password']

    db.update_vault_entry(entry_id, user_id, service_name, username_email, encrypted_pw, notes)
    flash(f'Credential for "{service_name}" updated successfully.', 'success')
    return redirect(url_for('dashboard'))

@app.route('/vault/delete/<int:entry_id>', methods=['POST'])
@login_required
@require_csrf
def delete_entry(entry_id):
    user_id = session['user_id']
    if db.delete_vault_entry(entry_id, user_id):
        flash('Credential removed from vault.', 'success')
    else:
        flash('Failed to delete entry or unauthorized.', 'danger')
    return redirect(url_for('dashboard'))

@app.route('/vault/decrypt/<int:entry_id>', methods=['POST'])
@login_required
@require_csrf
def decrypt_entry(entry_id):
    user_id = session['user_id']
    vault_key = session.get('vault_key')

    if not vault_key:
        return jsonify({'success': False, 'error': 'Encryption key unavailable.'}), 401

    entry = db.get_vault_entry_by_id(entry_id, user_id)
    if not entry:
        return jsonify({'success': False, 'error': 'Entry not found.'}), 404

    try:
        decrypted_password = crypto.decrypt_credential(entry['encrypted_password'], vault_key.encode('utf-8'))
        return jsonify({'success': True, 'password': decrypted_password})
    except Exception as e:
        return jsonify({'success': False, 'error': f'Decryption failed: {str(e)}'}), 400

@app.route('/api/generate-password', methods=['POST'])
@login_required
@require_csrf
def api_generate_password():
    data = request.get_json() or {}
    length = int(data.get('length', 16))
    use_upper = bool(data.get('upper', True))
    use_lower = bool(data.get('lower', True))
    use_digits = bool(data.get('digits', True))
    use_symbols = bool(data.get('symbols', True))

    password = crypto.generate_secure_password(
        length=length,
        use_upper=use_upper,
        use_lower=use_lower,
        use_digits=use_digits,
        use_symbols=use_symbols
    )
    analysis = crypto.evaluate_password_strength(password)

    return jsonify({
        'success': True,
        'password': password,
        'analysis': analysis
    })

if __name__ == '__main__':
    db.init_db()
    app.run(host='127.0.0.1', port=5000, debug=True)
