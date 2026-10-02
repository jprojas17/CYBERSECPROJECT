# Unit Tests: Security Defenses, Rate Limiting, CSRF Protection, and Headers
import pytest
import re
from app import app
import security

# Test anti-brute-force rate limiter
def test_rate_limiter_lockout():
    test_ip = "192.168.1.99"
    security.reset_failed_attempts(test_ip)

    # 4 failed attempts should not lock yet
    for _ in range(4):
        security.record_failed_attempt(test_ip)
        locked, _ = security.is_ip_locked(test_ip)
        assert locked is False

    # 5th failed attempt must trigger lockout
    security.record_failed_attempt(test_ip)
    locked, remaining = security.is_ip_locked(test_ip)
    assert locked is True
    assert remaining > 0

    # Resetting restores access
    security.reset_failed_attempts(test_ip)
    locked, _ = security.is_ip_locked(test_ip)
    assert locked is False

# Test CSRF Protection rejects unauthorized POST requests
def test_csrf_protection_rejects_missing_token():
    client = app.test_client()
    res = client.post('/register', data={
        'username': 'attacker',
        'master_password': 'Password123!',
        'confirm_password': 'Password123!'
    })
    # Must be 403 Forbidden due to missing CSRF token
    assert res.status_code == 403

# Test Security Headers presence on all HTTP responses
def test_security_headers_present():
    client = app.test_client()
    res = client.get('/login')
    
    assert res.headers.get('X-Content-Type-Options') == 'nosniff'
    assert res.headers.get('X-Frame-Options') == 'DENY'
    assert 'Content-Security-Policy' in res.headers

# Test authentication requirement on protected dashboard route
def test_unauthenticated_dashboard_redirect():
    client = app.test_client()
    res = client.get('/dashboard')
    # Unauthenticated access is unauthorized (401)
    assert res.status_code == 401
