# Intentionally vulnerable test fixture for CyberGuard SAST testing.
# DO NOT USE IN PRODUCTION.

import hashlib
import sqlite3

def authenticate(username, password):
    # Rule CG-SQLI-001: SQL Injection via unparameterized string concatenation
    query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute(query)
    return cursor.fetchone()

def hash_password(password):
    # Rule CG-CRYP-001: Insecure MD5 hashing
    return hashlib.md5(password.encode()).hexdigest()
