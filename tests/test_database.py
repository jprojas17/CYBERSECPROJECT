# Unit tests for database module
import os
import unittest
import tempfile
import database
import crypto_utils

class TestDatabaseModule(unittest.TestCase):
    def setUp(self):
        # Create unique temporary database file
        temp_dir = tempfile.gettempdir()
        self.db_path = os.path.join(temp_dir, f"test_pm_{os.urandom(8).hex()}.db")
        database.init_db(self.db_path)

    def tearDown(self):
        if os.path.exists(self.db_path):
            try:
                os.remove(self.db_path)
            except OSError:
                pass

    def test_user_creation_and_retrieval(self):
        salt = crypto_utils.generate_salt()
        pwd_hash = crypto_utils.hash_master_password("MasterPass123!", salt)
        user_id = database.create_user("testuser", pwd_hash, salt, self.db_path)
        self.assertIsInstance(user_id, int)

        user = database.get_user_by_username("testuser", self.db_path)
        self.assertIsNotNone(user)
        self.assertEqual(user["username"], "testuser")
        self.assertEqual(user["master_password_hash"], pwd_hash)
        self.assertEqual(user["salt"], salt)

    def test_duplicate_user_rejection(self):
        salt = crypto_utils.generate_salt()
        pwd_hash = crypto_utils.hash_master_password("MasterPass123!", salt)
        database.create_user("alice", pwd_hash, salt, self.db_path)
        
        # Creating duplicate username should raise error
        with self.assertRaises(Exception):
            database.create_user("alice", pwd_hash, salt, self.db_path)

    def test_vault_entry_crud_and_search(self):
        salt = crypto_utils.generate_salt()
        pwd_hash = crypto_utils.hash_master_password("MasterPass123!", salt)
        user_id = database.create_user("bob", pwd_hash, salt, self.db_path)

        # Derive Fernet key and encrypt password
        key = crypto_utils.derive_key("MasterPass123!", salt)
        encrypted_pass = crypto_utils.encrypt_credential("SuperSecret99$", key)

        # Create entry
        entry_id = database.create_vault_entry(
            user_id=user_id,
            title="GitHub Account",
            username_or_email="bob@github.com",
            encrypted_password=encrypted_pass,
            website_url="https://github.com",
            notes="Personal dev",
            category="Development",
            db_path=self.db_path
        )
        self.assertIsInstance(entry_id, int)

        # Read entry
        entry = database.get_vault_entry_by_id(entry_id, user_id, self.db_path)
        self.assertIsNotNone(entry)
        self.assertEqual(entry["title"], "GitHub Account")
        decrypted = crypto_utils.decrypt_credential(entry["encrypted_password"], key)
        self.assertEqual(decrypted, "SuperSecret99$")

        # Update entry
        new_encrypted = crypto_utils.encrypt_credential("UpdatedSecret100$", key)
        updated = database.update_vault_entry(
            entry_id=entry_id,
            user_id=user_id,
            title="GitHub Main Account",
            username_or_email="bob@github.com",
            encrypted_password=new_encrypted,
            website_url="https://github.com",
            notes="Updated notes",
            category="Development",
            db_path=self.db_path
        )
        self.assertTrue(updated)

        # Verify update
        entry = database.get_vault_entry_by_id(entry_id, user_id, self.db_path)
        self.assertEqual(entry["title"], "GitHub Main Account")
        self.assertEqual(crypto_utils.decrypt_credential(entry["encrypted_password"], key), "UpdatedSecret100$")

        # Search filter
        results = database.get_vault_entries_by_user(user_id, search_query="GitHub", db_path=self.db_path)
        self.assertEqual(len(results), 1)

        # Delete entry
        deleted = database.delete_vault_entry(entry_id, user_id, self.db_path)
        self.assertTrue(deleted)
        self.assertIsNone(database.get_vault_entry_by_id(entry_id, user_id, self.db_path))

    def test_audit_logging(self):
        log_id = database.log_security_event(
            user_id=None,
            event_type="SYSTEM_BOOT",
            description="System initialized",
            ip_address="127.0.0.1",
            db_path=self.db_path
        )
        self.assertIsInstance(log_id, int)
        logs = database.get_audit_logs(None, limit=10, db_path=self.db_path)
        self.assertTrue(len(logs) >= 1)
        self.assertEqual(logs[0]["event_type"], "SYSTEM_BOOT")

if __name__ == "__main__":
    unittest.main()
