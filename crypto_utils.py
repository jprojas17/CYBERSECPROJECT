# Module: Cryptographic Engine for Secure Password Manager
import os
import math
import string
import secrets
import base64
import hmac
from typing import Dict, Any

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet, InvalidToken

# Cryptographic parameters
PBKDF2_ITERATIONS = 100_000
SALT_SIZE_BYTES = 16
KEY_LENGTH_BYTES = 32

# Generate a secure random salt (16 bytes)
def generate_salt(size: int = SALT_SIZE_BYTES) -> bytes:
    return secrets.token_bytes(size)

# Derive a 256-bit Fernet key using PBKDF2-HMAC-SHA256
def derive_key(master_password: str, salt: bytes, iterations: int = PBKDF2_ITERATIONS) -> bytes:
    if not isinstance(master_password, str) or not master_password:
        raise ValueError("Master password must be a non-empty string.")
    if not isinstance(salt, bytes) or len(salt) < 16:
        raise ValueError("Salt must be at least 16 bytes.")

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH_BYTES,
        salt=salt,
        iterations=iterations
    )
    raw_key = kdf.derive(master_password.encode('utf-8'))
    return base64.urlsafe_b64encode(raw_key)

# Hash master password with salt for authentication
def hash_master_password(master_password: str, salt: bytes) -> str:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH_BYTES,
        salt=salt,
        iterations=PBKDF2_ITERATIONS
    )
    derived = kdf.derive(master_password.encode('utf-8'))
    return derived.hex()

# Verify master password using constant-time comparison
def verify_master_password(provided_password: str, salt: bytes, expected_hash_hex: str) -> bool:
    try:
        calculated_hash_hex = hash_master_password(provided_password, salt)
        return hmac.compare_digest(calculated_hash_hex, expected_hash_hex)
    except Exception:
        return False

# Encrypt credential using Fernet (AES-128-CBC + HMAC)
def encrypt_credential(plaintext: str, fernet_key: bytes) -> str:
    if not isinstance(plaintext, str):
        raise TypeError("Plaintext credential must be a string.")
    f = Fernet(fernet_key)
    return f.encrypt(plaintext.encode('utf-8')).decode('utf-8')

# Decrypt credential using Fernet
def decrypt_credential(ciphertext_token: str, fernet_key: bytes) -> str:
    try:
        f = Fernet(fernet_key)
        return f.decrypt(ciphertext_token.encode('utf-8')).decode('utf-8')
    except InvalidToken:
        raise ValueError("Decryption failed: Invalid key or tampered data.")
    except Exception as e:
        raise ValueError(f"Decryption error: {str(e)}")

# Generate secure random password
def generate_secure_password(
    length: int = 16,
    use_upper: bool = True,
    use_lower: bool = True,
    use_digits: bool = True,
    use_symbols: bool = True
) -> str:
    length = max(8, length)
    char_pools = []
    guaranteed_chars = []

    if use_upper:
        char_pools.append(string.ascii_uppercase)
        guaranteed_chars.append(secrets.choice(string.ascii_uppercase))
    if use_lower:
        char_pools.append(string.ascii_lowercase)
        guaranteed_chars.append(secrets.choice(string.ascii_lowercase))
    if use_digits:
        char_pools.append(string.digits)
        guaranteed_chars.append(secrets.choice(string.digits))
    if use_symbols:
        symbols = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        char_pools.append(symbols)
        guaranteed_chars.append(secrets.choice(symbols))

    if not char_pools:
        char_pools = [string.ascii_letters + string.digits]
        guaranteed_chars.append(secrets.choice(string.ascii_letters))

    combined_pool = "".join(char_pools)
    remaining_length = length - len(guaranteed_chars)
    
    random_chars = [secrets.choice(combined_pool) for _ in range(remaining_length)]
    password_list = guaranteed_chars + random_chars
    
    # Shuffle characters using CSPRNG
    for i in range(len(password_list) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        password_list[i], password_list[j] = password_list[j], password_list[i]

    return "".join(password_list)

# Calculate entropy in bits: E = L * log2(R)
def calculate_entropy(password: str) -> float:
    if not password:
        return 0.0

    pool_size = 0
    if any(c in string.ascii_lowercase for c in password):
        pool_size += 26
    if any(c in string.ascii_uppercase for c in password):
        pool_size += 26
    if any(c in string.digits for c in password):
        pool_size += 10
    if any(c in string.punctuation or c in " !@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
        pool_size += 32

    if pool_size == 0:
        pool_size = 26

    entropy = len(password) * math.log2(pool_size)
    return round(entropy, 2)

# Evaluate password strength
def evaluate_password_strength(password: str) -> Dict[str, Any]:
    entropy = calculate_entropy(password)
    length = len(password)
    feedback = []

    if length < 10:
        feedback.append("Password is too short (minimum 10 chars).")
    if not any(c in string.ascii_uppercase for c in password):
        feedback.append("Add uppercase letters.")
    if not any(c in string.ascii_lowercase for c in password):
        feedback.append("Add lowercase letters.")
    if not any(c in string.digits for c in password):
        feedback.append("Add numbers.")
    if not any(c in string.punctuation for c in password):
        feedback.append("Add symbols.")

    if entropy < 35 or length < 8:
        rating = "Very Weak"
        score = min(25, int(entropy))
    elif entropy < 55:
        rating = "Weak"
        score = 40
    elif entropy < 75:
        rating = "Moderate"
        score = 65
    elif entropy < 95:
        rating = "Strong"
        score = 85
    else:
        rating = "Very Strong"
        score = 100

    return {
        "entropy": entropy,
        "score": score,
        "rating": rating,
        "length": length,
        "feedback": feedback
    }
