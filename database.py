# Module: SQLite Database Layer with Parameterized Queries (Anti-SQLi)
import sqlite3
import os
from typing import Optional, List, Dict, Any

# Resolve database file path (supports test override via env variable)
def get_db_path() -> str:
    return os.environ.get('DATABASE_PATH', os.path.join(os.path.dirname(__file__), 'vault.db'))

# Connect to SQLite database with foreign key support
def get_db_connection(db_path: Optional[str] = None):
    target_path = db_path or get_db_path()
    conn = sqlite3.connect(target_path, timeout=30.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn

# Initialize tables schema
def init_db(db_path: Optional[str] = None):
    conn = get_db_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                master_hash TEXT NOT NULL,
                salt BLOB NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS vault_entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                service_name TEXT NOT NULL,
                username_email TEXT NOT NULL,
                encrypted_password TEXT NOT NULL,
                notes TEXT DEFAULT '',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );
        """)
        conn.commit()
    finally:
        conn.close()

# Create a new user with salt and hashed master password
def create_user(username: str, master_hash: str, salt: bytes, db_path: Optional[str] = None) -> bool:
    conn = get_db_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO users (username, master_hash, salt) VALUES (?, ?, ?)",
            (username.strip(), master_hash, salt)
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    except Exception:
        return False
    finally:
        conn.close()

# Retrieve user record by username
def get_user_by_username(username: str, db_path: Optional[str] = None) -> Optional[sqlite3.Row]:
    conn = get_db_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username.strip(),))
        return cursor.fetchone()
    finally:
        conn.close()

# Retrieve user record by ID
def get_user_by_id(user_id: int, db_path: Optional[str] = None) -> Optional[sqlite3.Row]:
    conn = get_db_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        return cursor.fetchone()
    finally:
        conn.close()

# Add new encrypted credential entry
def add_vault_entry(user_id: int, service_name: str, username_email: str, encrypted_password: str, notes: str = "", db_path: Optional[str] = None) -> int:
    conn = get_db_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO vault_entries (user_id, service_name, username_email, encrypted_password, notes)
            VALUES (?, ?, ?, ?, ?)
            """,
            (user_id, service_name.strip(), username_email.strip(), encrypted_password, notes.strip())
        )
        entry_id = cursor.lastrowid
        conn.commit()
        return entry_id
    finally:
        conn.close()

# Get all vault entries for a specific user
def get_vault_entries_by_user(user_id: int, db_path: Optional[str] = None) -> List[sqlite3.Row]:
    conn = get_db_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM vault_entries WHERE user_id = ? ORDER BY service_name ASC",
            (user_id,)
        )
        return cursor.fetchall()
    finally:
        conn.close()

# Get specific vault entry with ownership validation
def get_vault_entry_by_id(entry_id: int, user_id: int, db_path: Optional[str] = None) -> Optional[sqlite3.Row]:
    conn = get_db_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM vault_entries WHERE id = ? AND user_id = ?",
            (entry_id, user_id)
        )
        return cursor.fetchone()
    finally:
        conn.close()

# Update existing vault entry
def update_vault_entry(entry_id: int, user_id: int, service_name: str, username_email: str, encrypted_password: str, notes: str = "", db_path: Optional[str] = None) -> bool:
    conn = get_db_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            UPDATE vault_entries
            SET service_name = ?, username_email = ?, encrypted_password = ?, notes = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND user_id = ?
            """,
            (service_name.strip(), username_email.strip(), encrypted_password, notes.strip(), entry_id, user_id)
        )
        rows_affected = cursor.rowcount
        conn.commit()
        return rows_affected > 0
    finally:
        conn.close()

# Delete vault entry
def delete_vault_entry(entry_id: int, user_id: int, db_path: Optional[str] = None) -> bool:
    conn = get_db_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute(
            "DELETE FROM vault_entries WHERE id = ? AND user_id = ?",
            (entry_id, user_id)
        )
        rows_affected = cursor.rowcount
        conn.commit()
        return rows_affected > 0
    finally:
        conn.close()
