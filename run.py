#!/usr/bin/env python3
# Secure Password Manager - 1-Click Automated Runner

import sys
import subprocess
import os

REQUIRED_PACKAGES = [
    "Flask>=3.0.0",
    "cryptography>=42.0.0"
]

def check_and_install_dependencies():
    # Verify required third-party libraries and install them if missing
    print("[*] Checking Python environment and dependencies...")
    missing_packages = []
    
    for package in REQUIRED_PACKAGES:
        pkg_name = package.split(">=")[0].strip()
        try:
            __import__(pkg_name.lower())
        except ImportError:
            missing_packages.append(package)

    if missing_packages:
        print(f"[!] Missing packages detected: {', '.join(missing_packages)}")
        print("[*] Installing dependencies automatically...")
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", *missing_packages])
            print("[+] All dependencies successfully installed.")
        except subprocess.CalledProcessError as e:
            print(f"[-] Error installing packages: {e}")
            sys.exit(1)
    else:
        print("[+] All required dependencies are satisfied.")

def initialize_database():
    # Initialize SQLite database if database module is present
    try:
        from database import init_db
        print("[*] Initializing SQLite database schema...")
        init_db()
        print("[+] Database initialized successfully.")
    except ImportError:
        print("[!] Database module not found yet; skipping DB initialization.")
    except Exception as e:
        print(f"[-] Database initialization notice: {e}")

def run_application():
    # Launch the Flask web application
    print("=" * 60)
    print("   SECURE PASSWORD MANAGER (B207 CYBER SECURITY)")
    print("   Starting server at: http://127.0.0.1:5000")
    print("   Press CTRL+C to terminate the application.")
    print("=" * 60)
    
    try:
        from app import app
        app.run(host="127.0.0.1", port=5000, debug=True)
    except ImportError:
        print("[!] App entrypoint (app.py) will be executed once implemented.")
    except Exception as e:
        print(f"[-] Application execution error: {e}")

if __name__ == "__main__":
    check_and_install_dependencies()
    initialize_database()
    run_application()
