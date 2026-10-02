#!/usr/bin/env python3
"""
VULNERABLE APPLICATION - For Security Audit Purposes
Cybersecurity Internship - Task 3 (Secure Coding Review)
Author: Umer Zafar

WARNING: This file intentionally contains security vulnerabilities
for educational/audit purposes. DO NOT use in production.
"""

import sqlite3
import os
import hashlib
import subprocess

# ------------------------------------------------------------------
# VULNERABILITY 1: Hardcoded credentials
# ------------------------------------------------------------------
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "SuperSecret123"   # Hardcoded password in source code
DATABASE_API_KEY = "sk_live_51H8xJ2KzL9mPq3RvT7wY"  # Hardcoded API key


# ------------------------------------------------------------------
# VULNERABILITY 2: SQL Injection
# ------------------------------------------------------------------
def get_user_by_username(username):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # Directly inserting user input into SQL query (no sanitization)
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    result = cursor.fetchall()
    conn.close()
    return result


# ------------------------------------------------------------------
# VULNERABILITY 3: Weak password hashing (MD5)
# ------------------------------------------------------------------
def hash_password(password):
    # MD5 is cryptographically broken, should never be used for passwords
    return hashlib.md5(password.encode()).hexdigest()


# ------------------------------------------------------------------
# VULNERABILITY 4: Command Injection
# ------------------------------------------------------------------
def ping_host(hostname):
    # User input passed directly into shell command
    command = "ping -c 1 " + hostname
    result = os.system(command)
    return result


# ------------------------------------------------------------------
# VULNERABILITY 5: Insecure file handling / Path Traversal
# ------------------------------------------------------------------
def read_user_file(filename):
    # No validation - user could pass "../../etc/passwd"
    filepath = "/home/user/files/" + filename
    with open(filepath, "r") as f:
        return f.read()


# ------------------------------------------------------------------
# VULNERABILITY 6: Insecure deserialization / eval usage
# ------------------------------------------------------------------
def calculate_expression(user_input):
    # Using eval() on user input is extremely dangerous
    result = eval(user_input)
    return result


# ------------------------------------------------------------------
# VULNERABILITY 7: Overly broad exception handling (hides errors)
# ------------------------------------------------------------------
def login(username, password):
    try:
        user = get_user_by_username(username)
        hashed = hash_password(password)
        if user and username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            return True
        return False
    except:
        # Bare except silently hides all errors, including security issues
        pass


# ------------------------------------------------------------------
# VULNERABILITY 8: Use of subprocess with shell=True
# ------------------------------------------------------------------
def list_directory(path):
    result = subprocess.run("ls -la " + path, shell=True, capture_output=True)
    return result.stdout


if __name__ == "__main__":
    print("Vulnerable App - Demo Mode")
    print(login("admin", "SuperSecret123"))
