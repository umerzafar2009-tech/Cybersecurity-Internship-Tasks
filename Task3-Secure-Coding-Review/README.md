# Task 3: Secure Coding Review

## 📌 Project Overview
This project demonstrates a secure code review process as part of a Cybersecurity Internship. A deliberately vulnerable Python application was created, audited using a static analysis tool (**Bandit**), manually reviewed, and then remediated into a secure version. This simulates a real-world **Application Security (AppSec)** workflow.

## 🎯 Objectives
- Build a sample application containing common security vulnerabilities
- Perform static code analysis to identify security issues
- Manually review and understand each vulnerability
- Remediate (fix) all identified issues
- Document findings, severity, and recommendations

## 🛠️ Tools & Technologies Used
- **Python 3** — Programming language audited
- **Bandit** — Static Application Security Testing (SAST) tool for Python
- **Kali Linux** — Operating environment

## 📂 Files in This Folder
| File | Description |
|------|-------------|
| `vulnerable_app.py` | Intentionally insecure application (before fixes) |
| `secure_app.py` | Remediated, secure version (after fixes) |
| `bandit_report.txt` | Bandit scan results on the vulnerable app |
| `secure_bandit_report.txt` | Bandit scan results on the secure app |
| `README.md` | Project documentation (this file) |

## 🔍 Vulnerabilities Identified & Remediation

| # | Vulnerability | CWE | Severity | Fix Applied |
|---|---|---|---|---|
| 1 | Hardcoded credentials & API key | CWE-259 | Low | Moved secrets to environment variables |
| 2 | SQL Injection (string concatenation in query) | CWE-89 | Medium | Used parameterized queries (`?` placeholders) |
| 3 | Weak password hashing (MD5) | CWE-327 | High | Replaced with salted PBKDF2-SHA256 hashing |
| 4 | Command Injection (`os.system`) | CWE-78 | High | Replaced with `subprocess.run()` using argument lists, no shell |
| 5 | Insecure use of `eval()` | CWE-78 | Medium | Replaced with `ast.literal_eval()` (safe parsing only) |
| 6 | Path Traversal in file reading | — | Medium (manual finding) | Added path validation using `os.path.realpath()` + prefix check |
| 7 | Bare `except: pass` (silent error handling) | CWE-703 | Low | Added specific exception handling with logging |
| 8 | `subprocess` with `shell=True` | CWE-78 | High | Removed `shell=True`, passed arguments as a list |

## 📊 Bandit Scan Results — Before vs After

| Severity | Vulnerable App | Secure App |
|----------|----------------|------------|
| High     | 3              | **0** ✅    |
| Medium   | 2              | **0** ✅    |
| Low      | 3              | 5*         |
| **Total**| **8**          | **5**      |

\* The 5 remaining "Low" severity findings in the secure version are generic informational warnings from Bandit about the `subprocess` module being used at all (not actual vulnerabilities). Since `shell=True` was removed and arguments are passed as a list, these calls are safe — Bandit flags any subprocess usage as a precaution regardless of how securely it's implemented.

## 🔍 Key Learnings
- **Never trust user input** — always validate, sanitize, or parameterize before using it in queries, commands, or file paths.
- **Parameterized queries** completely eliminate SQL injection risk by separating code from data.
- **MD5 and SHA1 are broken for password hashing** — modern applications should use salted PBKDF2, bcrypt, or Argon2.
- **`shell=True` and `os.system()` are dangerous** — they allow attacker-controlled input to execute arbitrary system commands.
- **`eval()` should never be used on untrusted input** — `ast.literal_eval()` is a safe alternative for parsing literals.
- Static analysis tools like Bandit are valuable, but **manual review is still necessary** — some issues (like path traversal in this project) require human judgment to identify and fix correctly.
- Not every tool warning indicates a real vulnerability — understanding **context and risk** is a critical skill in security auditing.

## ▶️ How to Reproduce This Audit

### 1. Install Bandit
```bash
pip3 install bandit --break-system-packages
```

### 2. Run Bandit on the vulnerable file
```bash
bandit vulnerable_app.py
```

### 3. Run Bandit on the secure file
```bash
bandit secure_app.py
```

### 4. Save results to a report file
```bash
bandit vulnerable_app.py -f txt -o bandit_report.txt
```

## 👤 Author
Umer Zafar — Cybersecurity Internship
