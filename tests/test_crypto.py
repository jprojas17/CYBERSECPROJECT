# Unit tests for cryptographic engine
import unittest
import crypto_utils

class TestCryptoUtils(unittest.TestCase):
    def test_salt_generation(self):
        salt1 = crypto_utils.generate_salt()
        salt2 = crypto_utils.generate_salt()
        self.assertEqual(len(salt1), 16)
        self.assertEqual(len(salt2), 16)
        self.assertNotEqual(salt1, salt2)

    def test_key_derivation_deterministic(self):
        salt = crypto_utils.generate_salt()
        key1 = crypto_utils.derive_key("MyMasterPass!123", salt)
        key2 = crypto_utils.derive_key("MyMasterPass!123", salt)
        self.assertEqual(key1, key2)

    def test_master_password_verification(self):
        salt = crypto_utils.generate_salt()
        pwd_hash = crypto_utils.hash_master_password("SecureMaster99$", salt)
        self.assertTrue(crypto_utils.verify_master_password("SecureMaster99$", salt, pwd_hash))
        self.assertFalse(crypto_utils.verify_master_password("WrongPassword99$", salt, pwd_hash))

    def test_encryption_decryption_cycle(self):
        salt = crypto_utils.generate_salt()
        key = crypto_utils.derive_key("ValidMasterPass1!", salt)
        plaintext = "SuperSecretBankPassword#2026"
        token = crypto_utils.encrypt_credential(plaintext, key)
        self.assertNotEqual(token, plaintext)
        decrypted = crypto_utils.decrypt_credential(token, key)
        self.assertEqual(decrypted, plaintext)

    def test_password_generation_and_entropy(self):
        pwd = crypto_utils.generate_secure_password(length=20)
        self.assertEqual(len(pwd), 20)
        analysis = crypto_utils.evaluate_password_strength(pwd)
        self.assertGreater(analysis["entropy"], 80)
        self.assertIn(analysis["rating"], ["Strong", "Very Strong"])

if __name__ == "__main__":
    unittest.main()
