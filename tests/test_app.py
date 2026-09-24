# Unit and integration tests for Flask web application
import os
import unittest
import tempfile
import json
from app import app
import database

class TestFlaskApp(unittest.TestCase):
    def setUp(self):
        # Create isolated temporary database for Flask tests
        temp_dir = tempfile.gettempdir()
        self.db_path = os.path.join(temp_dir, f"test_flask_app_{os.urandom(8).hex()}.db")
        database.init_db(self.db_path)
        
        # Monkeypatch database DB_FILE_PATH during test execution
        self.original_db_path = database.DB_FILE_PATH
        database.DB_FILE_PATH = self.db_path
        
        app.config["TESTING"] = True
        app.config["WTF_CSRF_ENABLED"] = False
        self.client = app.test_client()

    def tearDown(self):
        database.DB_FILE_PATH = self.original_db_path
        if os.path.exists(self.db_path):
            try:
                os.remove(self.db_path)
            except OSError:
                pass

    def test_registration_and_login_flow(self):
        # Register new user
        reg_resp = self.client.post("/register", data={
            "username": "sec_tester",
            "master_password": "ValidMasterPassword123!",
            "confirm_password": "ValidMasterPassword123!"
        }, follow_redirects=True)
        self.assertEqual(reg_resp.status_code, 200)
        self.assertIn(b"Account registered successfully", reg_resp.data)

        # Login with registered credentials
        login_resp = self.client.post("/login", data={
            "username": "sec_tester",
            "master_password": "ValidMasterPassword123!"
        }, follow_redirects=True)
        self.assertEqual(login_resp.status_code, 200)
        self.assertIn(b"Passwords & Credentials", login_resp.data)

    def test_vault_credential_lifecycle(self):
        # Register and login
        self.client.post("/register", data={
            "username": "vault_user",
            "master_password": "MasterSecretPass999!",
            "confirm_password": "MasterSecretPass999!"
        })
        self.client.post("/login", data={
            "username": "vault_user",
            "master_password": "MasterSecretPass999!"
        })

        # Add credential
        add_resp = self.client.post("/vault/add", data={
            "title": "ProtonMail Secret",
            "username_or_email": "privacy@proton.me",
            "password": "UltraSecretPassword#2026",
            "website_url": "https://proton.me",
            "category": "Personal",
            "notes": "Encrypted notes"
        }, follow_redirects=True)
        self.assertEqual(add_resp.status_code, 200)
        self.assertIn(b"ProtonMail Secret", add_resp.data)

        # Decrypt via API
        user = database.get_user_by_username("vault_user")
        entries = database.get_vault_entries_by_user(user["id"])
        self.assertEqual(len(entries), 1)
        entry_id = entries[0]["id"]

        decrypt_resp = self.client.post(f"/api/vault/decrypt/{entry_id}")
        self.assertEqual(decrypt_resp.status_code, 200)
        data = json.loads(decrypt_resp.data)
        self.assertTrue(data["success"])
        self.assertEqual(data["password"], "UltraSecretPassword#2026")

        # Delete credential
        del_resp = self.client.post(f"/vault/delete/{entry_id}", follow_redirects=True)
        self.assertEqual(del_resp.status_code, 200)
        self.assertIn(b"was deleted", del_resp.data)

    def test_api_password_generator(self):
        resp = self.client.post("/api/password/generate", json={
            "length": 24,
            "use_upper": True,
            "use_lower": True,
            "use_digits": True,
            "use_symbols": True
        })
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.data)
        self.assertTrue(data["success"])
        self.assertEqual(len(data["password"]), 24)
        self.assertGreater(data["strength"]["entropy"], 90)

    def test_audit_logs_accessible(self):
        # Register and login to generate logs
        self.client.post("/register", data={
            "username": "auditor",
            "master_password": "AuditPassword123!",
            "confirm_password": "AuditPassword123!"
        })
        self.client.post("/login", data={
            "username": "auditor",
            "master_password": "AuditPassword123!"
        })

        resp = self.client.get("/audit-logs")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Security Audit Trail", resp.data)

if __name__ == "__main__":
    unittest.main()
