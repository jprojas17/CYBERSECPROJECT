# Module: Web Application Core Server (Flask)
import os
import secrets
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, abort

import database
import crypto_utils

# Initialize Flask application with custom static and template paths
app = Flask(__name__, static_folder="src", template_folder="templates")
app.secret_key = os.environ.get("FLASK_SECRET_KEY", secrets.token_hex(32))
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

# Ensure database tables exist on startup
database.init_db()

# Security Middleware: Attach HTTP security headers to all responses
@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self' https://fonts.googleapis.com https://fonts.gstatic.com; "
        "script-src 'self'; "
        "style-src 'self' https://fonts.googleapis.com 'unsafe-inline'; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data:;"
    )
    return response

# Decorator to enforce authenticated session
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session or "derived_key" not in session:
            flash("Please log in to access your secure vault.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function

# Route: Root redirection
@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))

# Route: User registration
@app.route("/register", methods=["GET", "POST"])
def register():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
        
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        master_password = request.form.get("master_password", "")
        confirm_password = request.form.get("confirm_password", "")
        
        # Validation checks
        if not username or len(username) < 3:
            flash("Username must be at least 3 characters long.", "danger")
            return render_template("register.html")
            
        if len(master_password) < 8:
            flash("Master password must be at least 8 characters long.", "danger")
            return render_template("register.html")
            
        if master_password != confirm_password:
            flash("Passwords do not match.", "danger")
            return render_template("register.html")
            
        existing_user = database.get_user_by_username(username)
        if existing_user:
            flash("Username already exists. Please choose another.", "danger")
            return render_template("register.html")
            
        # Cryptographic derivation & hashing
        salt = crypto_utils.generate_salt()
        pwd_hash = crypto_utils.hash_master_password(master_password, salt)
        
        try:
            user_id = database.create_user(username, pwd_hash, salt)
            database.log_security_event(user_id, "USER_REGISTERED", f"Account created for user '{username}'", request.remote_addr)
            flash("Account registered successfully! You can now log in.", "success")
            return redirect(url_for("login"))
        except Exception as e:
            flash(f"Error registering user: {str(e)}", "danger")
            return render_template("register.html")
            
    return render_template("register.html")

# Route: User authentication / login
@app.route("/login", methods=["GET", "POST"])
def login():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
        
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        master_password = request.form.get("master_password", "")
        
        user = database.get_user_by_username(username)
        if not user:
            database.log_security_event(None, "LOGIN_FAILED", f"Failed login attempt for unknown user '{username}'", request.remote_addr)
            flash("Invalid username or master password.", "danger")
            return render_template("login.html")
            
        # Verify master password with constant-time check
        salt = user["salt"]
        stored_hash = user["master_password_hash"]
        
        if crypto_utils.verify_master_password(master_password, salt, stored_hash):
            # Derive 256-bit Fernet key for session credential encryption/decryption
            derived_key = crypto_utils.derive_key(master_password, salt)
            
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["derived_key"] = derived_key.decode("utf-8")
            
            database.log_security_event(user["id"], "LOGIN_SUCCESS", f"User '{username}' logged in successfully", request.remote_addr)
            flash(f"Welcome back, {username}!", "success")
            return redirect(url_for("dashboard"))
        else:
            database.log_security_event(user["id"], "LOGIN_FAILED", f"Invalid password attempt for user '{username}'", request.remote_addr)
            flash("Invalid username or master password.", "danger")
            return render_template("login.html")
            
    return render_template("login.html")

# Route: User logout
@app.route("/logout")
def logout():
    user_id = session.get("user_id")
    if user_id:
        database.log_security_event(user_id, "LOGOUT", f"User logged out", request.remote_addr)
    session.clear()
    flash("You have been securely logged out.", "success")
    return redirect(url_for("login"))

# Route: Main password vault dashboard
@app.route("/dashboard")
@login_required
def dashboard():
    user_id = session["user_id"]
    category = request.args.get("category", "All")
    search_query = request.args.get("q", "").strip()
    
    entries = database.get_vault_entries_by_user(user_id, category=category, search_query=search_query)
    categories = ["All", "General", "Work", "Social", "Finance", "Personal"]
    
    return render_template(
        "dashboard.html",
        entries=entries,
        categories=categories,
        current_category=category,
        search_query=search_query
    )

# Route: Add new vault entry
@app.route("/vault/add", methods=["POST"])
@login_required
def add_vault_entry():
    user_id = session["user_id"]
    fernet_key = session["derived_key"].encode("utf-8")
    
    title = request.form.get("title", "").strip()
    username_or_email = request.form.get("username_or_email", "").strip()
    raw_password = request.form.get("password", "")
    website_url = request.form.get("website_url", "").strip()
    category = request.form.get("category", "General").strip()
    notes = request.form.get("notes", "").strip()
    
    if not title or not raw_password:
        flash("Title and Password are required fields.", "danger")
        return redirect(url_for("dashboard"))
        
    try:
        encrypted_password = crypto_utils.encrypt_credential(raw_password, fernet_key)
        entry_id = database.create_vault_entry(
            user_id=user_id,
            title=title,
            username_or_email=username_or_email,
            encrypted_password=encrypted_password,
            website_url=website_url,
            notes=notes,
            category=category
        )
        database.log_security_event(user_id, "ENTRY_CREATED", f"Created credential '{title}' (ID: {entry_id})", request.remote_addr)
        flash(f"Credential '{title}' successfully added and encrypted.", "success")
    except Exception as e:
        flash(f"Error encrypting or saving credential: {str(e)}", "danger")
        
    return redirect(url_for("dashboard"))

# Route: Update existing vault entry
@app.route("/vault/update/<int:entry_id>", methods=["POST"])
@login_required
def update_vault_entry(entry_id: int):
    user_id = session["user_id"]
    fernet_key = session["derived_key"].encode("utf-8")
    
    existing_entry = database.get_vault_entry_by_id(entry_id, user_id)
    if not existing_entry:
        flash("Credential entry not found or unauthorized.", "danger")
        return redirect(url_for("dashboard"))
        
    title = request.form.get("title", "").strip()
    username_or_email = request.form.get("username_or_email", "").strip()
    new_raw_password = request.form.get("password", "").strip()
    website_url = request.form.get("website_url", "").strip()
    category = request.form.get("category", "General").strip()
    notes = request.form.get("notes", "").strip()
    
    if not title:
        flash("Title is required.", "danger")
        return redirect(url_for("dashboard"))
        
    # Use new encrypted password if provided, otherwise preserve current ciphertext
    if new_raw_password:
        encrypted_password = crypto_utils.encrypt_credential(new_raw_password, fernet_key)
    else:
        encrypted_password = existing_entry["encrypted_password"]
        
    success = database.update_vault_entry(
        entry_id=entry_id,
        user_id=user_id,
        title=title,
        username_or_email=username_or_email,
        encrypted_password=encrypted_password,
        website_url=website_url,
        notes=notes,
        category=category
    )
    
    if success:
        database.log_security_event(user_id, "ENTRY_UPDATED", f"Updated credential '{title}' (ID: {entry_id})", request.remote_addr)
        flash(f"Credential '{title}' updated successfully.", "success")
    else:
        flash("Failed to update credential entry.", "danger")
        
    return redirect(url_for("dashboard"))

# Route: Delete vault entry
@app.route("/vault/delete/<int:entry_id>", methods=["POST"])
@login_required
def delete_vault_entry(entry_id: int):
    user_id = session["user_id"]
    existing_entry = database.get_vault_entry_by_id(entry_id, user_id)
    
    if not existing_entry:
        flash("Entry not found.", "danger")
        return redirect(url_for("dashboard"))
        
    database.delete_vault_entry(entry_id, user_id)
    database.log_security_event(user_id, "ENTRY_DELETED", f"Deleted credential '{existing_entry['title']}' (ID: {entry_id})", request.remote_addr)
    flash(f"Credential '{existing_entry['title']}' was deleted.", "success")
    return redirect(url_for("dashboard"))

# API Route: Decrypt credential for viewing or copying in UI
@app.route("/api/vault/decrypt/<int:entry_id>", methods=["POST"])
@login_required
def api_decrypt_entry(entry_id: int):
    user_id = session["user_id"]
    fernet_key = session["derived_key"].encode("utf-8")
    
    entry = database.get_vault_entry_by_id(entry_id, user_id)
    if not entry:
        return jsonify({"success": False, "error": "Entry not found"}), 404
        
    try:
        decrypted_password = crypto_utils.decrypt_credential(entry["encrypted_password"], fernet_key)
        database.log_security_event(user_id, "ENTRY_DECRYPTED", f"Decrypted credential '{entry['title']}'", request.remote_addr)
        return jsonify({"success": True, "password": decrypted_password})
    except Exception as e:
        return jsonify({"success": False, "error": f"Decryption failure: {str(e)}"}), 500

# API Route: Generate secure password and entropy score
@app.route("/api/password/generate", methods=["POST"])
def api_generate_password():
    data = request.get_json() or {}
    length = int(data.get("length", 16))
    use_upper = bool(data.get("use_upper", True))
    use_lower = bool(data.get("use_lower", True))
    use_digits = bool(data.get("use_digits", True))
    use_symbols = bool(data.get("use_symbols", True))
    
    password = crypto_utils.generate_secure_password(length, use_upper, use_lower, use_digits, use_symbols)
    strength = crypto_utils.evaluate_password_strength(password)
    
    return jsonify({
        "success": True,
        "password": password,
        "strength": strength
    })

# Route: Security audit logs viewer
@app.route("/audit-logs")
@login_required
def audit_logs():
    user_id = session["user_id"]
    logs = database.get_audit_logs(user_id=user_id, limit=100)
    return render_template("audit_logs.html", logs=logs)

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
