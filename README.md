# JPTech Vault - Secure Password Manager

A secure password manager built with Python, Flask, SQLite, and authenticated AES-128 / Fernet encryption. Designed for the B207 Cyber Security coursework at Gisma University of Applied Sciences.

---

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

---

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

---

## Step-by-Step Feature Walkthrough

### 1. Account Registration
1. Navigate to `http://127.0.0.1:5000/register` (or click **"Create Account"** in the top navigation).
2. Enter a unique **Username** (e.g., `jprojas`).
3. Set your **Master Password** (minimum 10 characters, e.g., `MasterPass2026!`).
4. Re-enter the password in **Confirm Password**.
5. Click **"Create Account"**.
> **Security Under the Hood:** The application creates a 16-byte random salt using `secrets.token_bytes(16)`, hashes the master password with PBKDF2-HMAC-SHA256 (100,000 iterations), and stores only the salt and hash. The plaintext master password is never written to disk.

---

### 2. User Authentication (Login)
1. Navigate to `http://127.0.0.1:5000/login`.
2. Enter your **Username** and **Master Password**.
3. Click **"Sign In"**.
> **Security Under the Hood:** The server verifies the password in constant-time (`hmac.compare_digest`) to prevent timing side-channel attacks. Upon successful authentication, an in-memory encryption key is derived for the active session (`session['vault_key']`).

---

### 3. Adding a New Credential
1. From the Dashboard, click the white button **`+ New Credential`** (top right).
2. Fill in the modal fields:
   - **Service / Website Name:** e.g., `GitHub`, `ProtonMail`, `Google`.
   - **Account / Email:** e.g., `user@example.com`.
   - **Password:** Enter your password or click **"Generate"** to create a strong one.
   - **Notes (Optional):** Add 2FA recovery codes or security questions.
3. Click **"Save Credential"**.
> **Security Under the Hood:** The credential is encrypted in memory using authenticated Fernet (AES-128-CBC + HMAC-SHA256) and saved in SQLite via parameterized queries (`?`).

---

### 4. Generating Strong Passwords (CSPRNG & Entropy)
1. Click the **`⚡ Generator`** button in the top action bar (or within the Add modal).
2. Adjust the **Length Slider** (between 8 and 48 characters).
3. Toggle character pool checkboxes: Uppercase (`A-Z`), Lowercase (`a-z`), Numbers (`0-9`), Symbols (`!@#$%`).
4. Observe the real-time **Entropy score (in bits)** and the dynamic color-coded strength bar.
5. Click **"Copy"** to copy the generated password to your clipboard, or click **"Apply to Add Form"** to automatically insert it into the Add Credential form.

---

### 5. Viewing & Decrypting Passwords (On-Demand with Auto-Masking)
1. On your vault dashboard, all passwords appear masked as `••••••••••••`.
2. Click **"Reveal"** on any credential card.
3. The plaintext password will appear in green alongside a **"Copy"** button.
4. An **"Auto-hiding in 15s"** countdown will start automatically.
5. After 15 seconds, the password automatically re-masks itself to protect against shoulder-surfing attacks. (You can also click **"Hide"** to mask it immediately).

---

### 6. Copying Passwords to Clipboard
1. When a password is revealed (or when generated in the generator modal), click the **"Copy"** button.
2. A floating toast notification will appear in the bottom-right corner confirming: *"Password copied to clipboard!"*.

---

### 7. Searching and Filtering Credentials
1. Use the search bar at the top of the dashboard: *"Search credentials by service, email or notes..."*.
2. Type any keyword (e.g., `git`, `proton`, `personal`).
3. The dashboard cards will filter instantly in real-time without reloading the page.

---

### 8. Editing an Existing Credential
1. Click the edit icon (**`✏️`**) on the credential card you wish to update.
2. Modify the service name, email, or notes.
3. If you wish to change the password, enter a new one in the **New Password** field (leave it blank to keep the existing encrypted password).
4. Click **"Save Changes"**.

---

### 9. Deleting a Credential
1. Click the trash icon (**`🗑️`**) on the credential card.
2. Confirm the browser prompt (*"Are you sure you want to delete this credential?"*).
3. The record is permanently removed from the database.

---

### 10. Logging Out
1. Click **"Log out"** in the top navigation bar.
2. The active session and the in-memory encryption key are completely wiped from memory.

---

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

---

## Author
**Juan Pablo Rojas**  
B207 Cyber Security  
Gisma University of Applied Sciences

## License
Academic coursework project created by Juan Pablo Rojas for Gisma University of Applied Sciences. Distributed under the MIT License for academic evaluation purposes.
