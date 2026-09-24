# Module: Database Management Layer for Secure Password Manager
import sqlite3
import os
from contextlib import contextmanager
from typing import Optional, List, Dict, Any, Generator

DB_FILE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "password_manager.db")

# Context manager that ensures connection is closed and foreign keys are enabled
@contextmanager
def get_db_connection(db_path: Optional[str] = None) -> Generator[sqlite3.Connection, None, None]:
    target_path = db_path if db_path is not None else DB_FILE_PATH
    conn = sqlite3.connect(target_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    try:
        yield conn
    finally:
        conn.close()

# Initialize SQLite database schema
def init_db(db_path: Optional[str] = None) -> None:
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        
        # Create users table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL COLLATE NOCASE,
            master_password_hash TEXT NOT NULL,
            salt BLOB NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """)
        
        # Create vault entries table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS vault_entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            username_or_email TEXT,
            encrypted_password TEXT NOT NULL,
            website_url TEXT,
            notes TEXT,
            category TEXT DEFAULT 'General',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        );
        """)
        
        # Create security audit logs table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            event_type TEXT NOT NULL,
            description TEXT NOT NULL,
            ip_address TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        );
        """)
        
        # Create indexes for search and relation speed
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_vault_user_id ON vault_entries(user_id);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_vault_category ON vault_entries(category);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_user_id ON audit_logs(user_id);")
        
        conn.commit()

# Register a new user account
def create_user(username: str, master_password_hash: str, salt: bytes, db_path: Optional[str] = None) -> int:
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO users (username, master_password_hash, salt) VALUES (?, ?, ?);",
            (username.strip(), master_password_hash, salt)
        )
        conn.commit()
        return cursor.lastrowid

# Retrieve user by username
def get_user_by_username(username: str, db_path: Optional[str] = None) -> Optional[sqlite3.Row]:
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?;", (username.strip(),))
        return cursor.fetchone()

# Retrieve user by primary key ID
def get_user_by_id(user_id: int, db_path: Optional[str] = None) -> Optional[sqlite3.Row]:
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE id = ?;", (user_id,))
        return cursor.fetchone()

# Add an encrypted credential entry to vault
def create_vault_entry(
    user_id: int,
    title: str,
    username_or_email: Optional[str],
    encrypted_password: str,
    website_url: Optional[str] = None,
    notes: Optional[str] = None,
    category: str = "General",
    db_path: Optional[str] = None
) -> int:
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("""
        INSERT INTO vault_entries (user_id, title, username_or_email, encrypted_password, website_url, notes, category)
        VALUES (?, ?, ?, ?, ?, ?, ?);
        """, (user_id, title.strip(), username_or_email, encrypted_password, website_url, notes, category.strip()))
        conn.commit()
        return cursor.lastrowid

# List vault entries belonging to a specific user
def get_vault_entries_by_user(
    user_id: int,
    category: Optional[str] = None,
    search_query: Optional[str] = None,
    db_path: Optional[str] = None
) -> List[sqlite3.Row]:
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        query = "SELECT * FROM vault_entries WHERE user_id = ?"
        params: List[Any] = [user_id]
        
        if category and category.lower() != "all":
            query += " AND category = ?"
            params.append(category)
            
        if search_query:
            query += " AND (title LIKE ? OR username_or_email LIKE ? OR website_url LIKE ?)"
            wildcard = f"%{search_query.strip()}%"
            params.extend([wildcard, wildcard, wildcard])
            
        query += " ORDER BY updated_at DESC;"
        cursor.execute(query, params)
        return cursor.fetchall()

# Retrieve single vault entry for a user
def get_vault_entry_by_id(entry_id: int, user_id: int, db_path: Optional[str] = None) -> Optional[sqlite3.Row]:
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM vault_entries WHERE id = ? AND user_id = ?;",
            (entry_id, user_id)
        )
        return cursor.fetchone()

# Update existing vault entry
def update_vault_entry(
    entry_id: int,
    user_id: int,
    title: str,
    username_or_email: Optional[str],
    encrypted_password: str,
    website_url: Optional[str] = None,
    notes: Optional[str] = None,
    category: str = "General",
    db_path: Optional[str] = None
) -> bool:
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("""
        UPDATE vault_entries
        SET title = ?, username_or_email = ?, encrypted_password = ?, website_url = ?, notes = ?, category = ?, updated_at = CURRENT_TIMESTAMP
        WHERE id = ? AND user_id = ?;
        """, (title.strip(), username_or_email, encrypted_password, website_url, notes, category.strip(), entry_id, user_id))
        conn.commit()
        return cursor.rowcount > 0

# Delete vault entry
def delete_vault_entry(entry_id: int, user_id: int, db_path: Optional[str] = None) -> bool:
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM vault_entries WHERE id = ? AND user_id = ?;", (entry_id, user_id))
        conn.commit()
        return cursor.rowcount > 0

# Log security audit events
def log_security_event(
    user_id: Optional[int],
    event_type: str,
    description: str,
    ip_address: Optional[str] = None,
    db_path: Optional[str] = None
) -> int:
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("""
        INSERT INTO audit_logs (user_id, event_type, description, ip_address)
        VALUES (?, ?, ?, ?);
        """, (user_id, event_type, description, ip_address))
        conn.commit()
        return cursor.lastrowid

# Retrieve recent audit logs for a user or admin
def get_audit_logs(user_id: Optional[int] = None, limit: int = 50, db_path: Optional[str] = None) -> List[sqlite3.Row]:
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        if user_id is not None:
            cursor.execute(
                "SELECT * FROM audit_logs WHERE user_id = ? ORDER BY timestamp DESC LIMIT ?;",
                (user_id, limit)
            )
        else:
            cursor.execute(
                "SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT ?;",
                (limit,)
            )
        return cursor.fetchall()
