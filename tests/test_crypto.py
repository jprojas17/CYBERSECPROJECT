# Unit Tests: Cryptographic Engine and CSPRNG Generator
import pytest
import string
import crypto_utils as crypto

# Test salt generation randomness and size
def test_generate_salt():
    salt1 = crypto.generate_salt()
    salt2 = crypto.generate_salt()
    assert len(salt1) == 16
    assert len(salt2) == 16
    assert salt1 != salt2

# Test key derivation produces valid Fernet key
def test_derive_key():
    salt = crypto.generate_salt()
    key1 = crypto.derive_key("MasterPassword123!", salt)
    key2 = crypto.derive_key("MasterPassword123!", salt)
    key_other_salt = crypto.derive_key("MasterPassword123!", crypto.generate_salt())
    
    assert key1 == key2
    assert key1 != key_other_salt
    assert len(key1) == 44

# Test encryption and decryption roundtrip
def test_encrypt_decrypt_roundtrip():
    salt = crypto.generate_salt()
    key = crypto.derive_key("MyMasterSecretPass!", salt)
    secret_text = "SecretBankPassword#999"
    
    ciphertext = crypto.encrypt_credential(secret_text, key)
    assert ciphertext != secret_text
    
    decrypted = crypto.decrypt_credential(ciphertext, key)
    assert decrypted == secret_text

# Test ciphertext tampering detection (HMAC validation)
def test_decryption_tampering():
    salt = crypto.generate_salt()
    key = crypto.derive_key("MyMasterSecretPass!", salt)
    ciphertext = crypto.encrypt_credential("SecretData", key)
    
    # Tamper with the ciphertext token
    tampered = ciphertext[:-4] + "AAAA"
    with pytest.raises(ValueError):
        crypto.decrypt_credential(tampered, key)

# Test master password hashing and verification
def test_master_password_verification():
    salt = crypto.generate_salt()
    pw = "SuperSecureMasterKey2026!"
    hashed = crypto.hash_master_password(pw, salt)
    
    assert crypto.verify_master_password(pw, salt, hashed) is True
    assert crypto.verify_master_password("WrongPassword!", salt, hashed) is False

# Test CSPRNG password generator
def test_password_generator():
    pw = crypto.generate_secure_password(length=20, use_upper=True, use_lower=True, use_digits=True, use_symbols=True)
    assert len(pw) == 20
    assert any(c in string.ascii_uppercase for c in pw)
    assert any(c in string.ascii_lowercase for c in pw)
    assert any(c in string.digits for c in pw)
    assert any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in pw)

# Test entropy calculation
def test_entropy_calculation():
    weak_entropy = crypto.calculate_entropy("123456")
    strong_entropy = crypto.calculate_entropy("Kj9#mP2$vL8!zQ4@")
    assert strong_entropy > weak_entropy
    assert weak_entropy < 30
    assert strong_entropy > 80
