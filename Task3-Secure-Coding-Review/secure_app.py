#!/usr/bin/env python3
"""
SECURE APPLICATION - Fixed Version
Cybersecurity Internship - Task 3 (Secure Coding Review)
Author: Umer Zafar

This is the remediated version of vulnerable_app.py.
Each fix is explained in comments above the relevant function.
"""

import sqlite3
import os
import hashlib
import subprocess
import shlex
import ast
import getpass

# ------------------------------------------------------------------
# FIX 1: No hardcoded credentials.
# Secrets should come from environment variables or a secrets manager
# (e.g., AWS Secrets Manager, HashiCorp Vault), never from source code.
# ------------------------------------------------------------------
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "")
ADMIN_PASSWORD_HASH = os.environ.get("ADMIN_PASSWORD_HASH", "")  # store only the hash
DATABASE_API_KEY = os.environ.get("DATABASE_API_KEY", "")


# ------------------------------------------------------------------
# FIX 2: SQL Injection - use parameterized queries (placeholders)
# The database driver safely escapes user input instead of
# concatenating raw strings into the SQL command.
# ------------------------------------------------------------------
def get_user_by_username(username):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username = ?"
    cursor.execute(query, (username,))   # safe parameter binding
    result = cursor.fetchall()
    conn.close()
    return result


# ------------------------------------------------------------------
# FIX 3: Strong password hashing using salted hashing (PBKDF2/SHA-256)
# instead of unsalted MD5. In a real production app, use a dedicated
# library like bcrypt or argon2 for even stronger protection.
# ------------------------------------------------------------------
def hash_password(password, salt=None):
    if salt is None:
        salt = os.urandom(16)
    hashed = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    return salt.hex() + ":" + hashed.hex()


def verify_password(password, stored_hash):
    salt_hex, hash_hex = stored_hash.split(":")
    salt = bytes.fromhex(salt_hex)
    new_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    return new_hash.hex() == hash_hex


# ------------------------------------------------------------------
# FIX 4: Command Injection - avoid shell commands entirely when
# possible. Use Python's built-in libraries instead of os.system().
# If a shell command is unavoidable, use subprocess with a list
# (no shell=True) and validate input strictly.
# ------------------------------------------------------------------
def ping_host(hostname):
    # Validate hostname format first (basic allow-list check)
    import re
    if not re.match(r'^[a-zA-Z0-9.\-]+$', hostname):
        raise ValueError("Invalid hostname format")

    # No shell=True, arguments passed as a list (prevents injection)
    result = subprocess.run(
        ["ping", "-c", "1", hostname],
        capture_output=True,
        text=True,
        timeout=5
    )
    return result.stdout


# ------------------------------------------------------------------
# FIX 5: Path Traversal - validate and restrict file access to a
# known safe directory using os.path.realpath and a prefix check.
# ------------------------------------------------------------------
def read_user_file(filename):
    safe_dir = os.path.realpath("/home/user/files/")
    requested_path = os.path.realpath(os.path.join(safe_dir, filename))

    # Ensure the resolved path is still inside the safe directory
    if not requested_path.startswith(safe_dir):
        raise ValueError("Access denied: path traversal attempt detected")

    with open(requested_path, "r") as f:
        return f.read()


# ------------------------------------------------------------------
# FIX 6: Never use eval() on user input. Use ast.literal_eval()
# which only parses safe literal values (numbers, strings, lists)
# and cannot execute arbitrary code.
# ------------------------------------------------------------------
def calculate_expression(user_input):
    try:
        result = ast.literal_eval(user_input)
        return result
    except (ValueError, SyntaxError):
        raise ValueError("Invalid expression")


# ------------------------------------------------------------------
# FIX 7: Specific exception handling with logging instead of a
# bare except/pass. This ensures errors are visible and auditable.
# ------------------------------------------------------------------
import logging
logging.basicConfig(filename='app.log', level=logging.ERROR)

def login(username, password):
    try:
        user = get_user_by_username(username)
        if user and username == ADMIN_USERNAME and verify_password(password, ADMIN_PASSWORD_HASH):
            return True
        return False
    except sqlite3.Error as db_err:
        logging.error(f"Database error during login: {db_err}")
        return False
    except Exception as e:
        logging.error(f"Unexpected error during login: {e}")
        return False


# ------------------------------------------------------------------
# FIX 8: No shell=True. Pass arguments as a list and validate path.
# ------------------------------------------------------------------
def list_directory(path):
    safe_base = os.path.realpath("/home/user/")
    target = os.path.realpath(path)
    if not target.startswith(safe_base):
        raise ValueError("Access denied: path outside allowed directory")

    result = subprocess.run(["ls", "-la", target], capture_output=True, text=True)
    return result.stdout


if __name__ == "__main__":
    print("Secure App - Demo Mode")
    print("All known vulnerabilities from vulnerable_app.py have been remediated.")
