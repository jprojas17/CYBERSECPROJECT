# Module: Security Middlewares, Anti-Brute-Force Rate Limiting, and CSRF Protection
import time
import secrets
from functools import wraps
from flask import request, session, abort, render_template

# Anti-Brute-Force Tracker (stores IP/user -> [attempt_count, lockout_timestamp])
FAILED_ATTEMPTS = {}
MAX_ATTEMPTS = 5
LOCKOUT_DURATION_SECONDS = 180

# Check if an IP address is currently locked out
def is_ip_locked(ip_address: str) -> tuple[bool, int]:
    current_time = time.time()
    record = FAILED_ATTEMPTS.get(ip_address)
    
    if not record:
        return False, 0
    
    attempts, lock_until = record
    if lock_until > current_time:
        remaining_seconds = int(lock_until - current_time)
        return True, remaining_seconds
    elif lock_until != 0 and lock_until <= current_time:
        # Lockout expired, reset tracker
        FAILED_ATTEMPTS.pop(ip_address, None)
        return False, 0
    
    return False, 0

# Record failed login attempt
def record_failed_attempt(ip_address: str):
    current_time = time.time()
    record = FAILED_ATTEMPTS.get(ip_address, [0, 0])
    attempts, _ = record
    attempts += 1
    
    if attempts >= MAX_ATTEMPTS:
        lock_until = current_time + LOCKOUT_DURATION_SECONDS
        FAILED_ATTEMPTS[ip_address] = [attempts, lock_until]
    else:
        FAILED_ATTEMPTS[ip_address] = [attempts, 0]

# Reset failed attempts upon successful login
def reset_failed_attempts(ip_address: str):
    FAILED_ATTEMPTS.pop(ip_address, None)

# Generate or retrieve unique anti-CSRF token per session
def get_or_create_csrf_token() -> str:
    if '_csrf_token' not in session:
        session['_csrf_token'] = secrets.token_hex(32)
    return session['_csrf_token']

# CSRF validation decorator for state-changing HTTP methods
def require_csrf(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.method in ["POST", "PUT", "DELETE"]:
            token = request.form.get('csrf_token') or request.headers.get('X-CSRF-Token')
            expected_token = session.get('_csrf_token')
            
            if not token or not expected_token or not secrets.compare_digest(token, expected_token):
                abort(403, description="CSRF Token validation failed or missing.")
        return f(*args, **kwargs)
    return decorated_function

# Require authenticated active session decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('user_id'):
            return render_template('login.html', error="Please authenticate to access your vault."), 401
        return f(*args, **kwargs)
    return decorated_function

# Inject strict security HTTP response headers
def apply_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "script-src 'self'; "
        "img-src 'self' data:;"
    )
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response
