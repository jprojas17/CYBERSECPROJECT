# Unit Tests: Database Operations and Anti-SQL Injection Defenses
import pytest
import uuid
import database as db

# Test user creation and duplicate prevention
def test_create_user_and_uniqueness():
    username = f"user_{uuid.uuid4().hex[:8]}"
    master_hash = "mockhash12345"
    salt = b"1234567890abcdef"
    
    created = db.create_user(username, master_hash, salt)
    assert created is True
    
    # Duplicate creation must fail gracefully
    duplicate = db.create_user(username, master_hash, salt)
    assert duplicate is False

# Test vault CRUD lifecycle
def test_vault_crud_lifecycle():
    username = f"crud_{uuid.uuid4().hex[:8]}"
    salt = b"1234567890123456"
    db.create_user(username, "hash", salt)
    user = db.get_user_by_username(username)
    user_id = user["id"]

    # 1. Add Entry
    entry_id = db.add_vault_entry(user_id, "Amazon", "buyer@amazon.com", "gAAAAAB...", "Prime Account")
    assert entry_id > 0

    # 2. Get Entry
    entry = db.get_vault_entry_by_id(entry_id, user_id)
    assert entry is not None
    assert entry["service_name"] == "Amazon"
    assert entry["notes"] == "Prime Account"

    # 3. Update Entry
    updated = db.update_vault_entry(entry_id, user_id, "Amazon AWS", "admin@aws.com", "gAAAAABNew...", "Updated notes")
    assert updated is True
    
    updated_entry = db.get_vault_entry_by_id(entry_id, user_id)
    assert updated_entry["service_name"] == "Amazon AWS"

    # 4. Delete Entry
    deleted = db.delete_vault_entry(entry_id, user_id)
    assert deleted is True
    assert db.get_vault_entry_by_id(entry_id, user_id) is None

# Test SQL Injection resistance with malicious payloads
def test_sql_injection_defense():
    sqli_payload = "' OR '1'='1' --"
    user = db.get_user_by_username(sqli_payload)
    assert user is None
