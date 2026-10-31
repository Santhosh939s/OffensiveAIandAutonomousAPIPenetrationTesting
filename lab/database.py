"""Database management for the Local API Security Laboratory.

Uses SQLite to maintain dummy test accounts and catalog data.
Supports both in-memory databases (for isolated unit tests) and file-based databases.
"""

import sqlite3
from typing import Any, Dict, List, Optional


class LabDatabase:
    """SQLite wrapper for the local vulnerable test lab."""

    def __init__(self, db_path: str = ":memory:"):
        self.db_path = db_path
        self._shared_conn: Optional[sqlite3.Connection] = None
        if db_path == ":memory:":
            self._shared_conn = sqlite3.connect(":memory:", check_same_thread=False)
            self._shared_conn.row_factory = sqlite3.Row
        self.init_schema()

    def get_connection(self) -> sqlite3.Connection:
        if self._shared_conn is not None:
            return self._shared_conn
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def init_schema(self) -> None:
        """Create tables for vulnerable lab demonstrations."""
        conn = self.get_connection()
        with conn:
            cursor = conn.cursor()

            # 1. Users table (includes sensitive fields prone to IDOR and mass-assignment)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL,
                    full_name TEXT NOT NULL,
                    email TEXT NOT NULL,
                    role TEXT NOT NULL DEFAULT 'user',
                    is_admin INTEGER NOT NULL DEFAULT 0,
                    api_token TEXT NOT NULL
                )
            """)

            # 2. Items / products catalog (for search and input injection demonstrations)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS items (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    description TEXT NOT NULL,
                    price REAL NOT NULL,
                    owner_id INTEGER NOT NULL,
                    FOREIGN KEY(owner_id) REFERENCES users(id)
                )
            """)

    def execute_query(self, query: str, params: Optional[tuple] = None) -> List[Dict[str, Any]]:
        """Execute a SELECT query and return list of dict rows."""
        conn = self.get_connection()
        cursor = conn.cursor()
        if params:
            cursor.execute(query, params)
        else:
            cursor.execute(query)
        rows = cursor.fetchall()
        return [dict(r) for r in rows]

    def execute_raw_unsafe_query(self, query: str) -> List[Dict[str, Any]]:
        """Intentionally unsafe query execution method for demonstrating simulated SQL errors."""
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(query)
        rows = cursor.fetchall()
        return [dict(r) for r in rows]

    def execute_commit(self, query: str, params: Optional[tuple] = None) -> int:
        """Execute an INSERT/UPDATE/DELETE query and return lastrowid."""
        conn = self.get_connection()
        with conn:
            cursor = conn.cursor()
            if params:
                cursor.execute(query, params)
            else:
                cursor.execute(query)
            return cursor.lastrowid

