# JPTech Vault - Secure Password Manager

A secure password manager built with Python, Flask, SQLite, and authenticated AES-128 / Fernet encryption. Designed for the B207 Cyber Security coursework at Gisma University of Applied Sciences.

## Features

- **Authenticated Symmetric Encryption:** Credentials encrypted at rest using Fernet (AES-128-CBC + HMAC-SHA256).
- **Zero-Knowledge Key Derivation:** Master passwords hashed and keys derived with PBKDF2-HMAC-SHA256 (100,000 iterations) with 16-byte random salts.
- **Defensive Web Security:**
  - Strict parameterized SQLite queries (Anti-SQLi).
  - Cryptographic per-session CSRF token validation.
  - Brute-force rate limiter (180s lockout after 5 consecutive failed attempts).
  - Hardened HTTP security headers (`CSP`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`).
- **Minimalist Web Dashboard:**
  - Modern dark zinc UI.
  - On-demand decryption with 15-second automatic masking countdown.
  - One-click copy to clipboard with toast notification.
  - CSPRNG password generator with real-time entropy calculation.
- **1-Click Execution:** Automated setup checking and installing dependencies automatically.

## Quick Start

### 1. Prerequisites
- Python 3.10 or higher.

### 2. Run the Application
**Windows:**
Double click `run.bat` or run:
```cmd
python run.py
```

**Linux / macOS:**
```bash
chmod +x run.sh
./run.sh
```

The application will start at `http://127.0.0.1:5000`.

### 3. Running Automated Tests
Run the test suite with `pytest`:
```bash
pytest tests/ -v
```

All 14 unit and security tests will execute and verify cryptographic integrity, database defenses, rate limiting, and CSRF protection.

## Project Structure

```text
├── app.py                # Flask application & routing controller
├── crypto_utils.py       # PBKDF2 derivation, Fernet encryption, CSPRNG generator
├── database.py           # SQLite database layer with parameterized queries
├── security.py           # Rate limiting, CSRF protection, and security headers
├── run.py                # 1-Click automated execution script
├── run.bat               # Windows batch launcher
├── run.sh                # Linux/macOS launcher script
├── conftest.py           # Pytest test configuration & isolation
├── src/
│   ├── css/style.css     # Shadcn-inspired dark styling
│   └── js/app.js         # Frontend vault interactions, timer & generator
├── templates/
│   ├── base.html         # Base layout & navigation
│   ├── login.html        # Sign in view
│   ├── register.html     # Account registration view
│   └── dashboard.html    # Vault credentials dashboard & modals
├── tests/
│   ├── test_crypto.py    # Cryptography unit tests
│   ├── test_database.py  # Database & SQLi tests
│   └── test_security.py  # Rate limiting & CSRF tests
└── README.md             # Project documentation
```

## Author
**Juan Pablo Rojas**  
B207 Cyber Security  
Gisma University of Applied Sciences

## License
Academic coursework project created by Juan Pablo Rojas for Gisma University of Applied Sciences. Distributed under the MIT License for academic evaluation purposes.
