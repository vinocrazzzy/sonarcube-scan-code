#!/usr/bin/env python3
"""
sonar_trap.py

A single-file "application" that intentionally contains:
- SQL injection
- Hardcoded credentials
- Weak cryptography (MD5)
- Insecure network calls (verify=False)
- Command injection via subprocess
- Resource leaks and missing context managers
- Repeated/duplicated code blocks
- Complex branching and nested loops
- Global mutable state
- Unused variables and dead code
- Busy-wait and inefficient constructs

This is intentionally bad code for static analysis practice.
"""

import os
import sys
import sqlite3
import hashlib
import base64
import subprocess
import threading
import time
import random
import json
import re
import ssl
from urllib import request as urllib_request
from http.client import HTTPSConnection
from typing import Optional, Any

# ------------------------------
# Global configuration & secrets
# ------------------------------
DB_PATH = "users_bad.db"                   # hardcoded path
ADMIN_PASSWORD = "P@ssw0rd123"             # hardcoded credential (bad)
API_TOKEN = "TOKEN_ABC_123_DEF"            # hardcoded token
DEFAULT_TIMEOUT = 5
VERBOSE = True

# Global mutable cache (bad practice)
GLOBAL_CACHE = {}

# ------------------------------
# Utility / duplicated helpers
# ------------------------------
def log(msg: str):
    """Simple logger with global verbose toggle."""
    if VERBOSE:
        print(f"[LOG] {msg}")

def log_debug(msg: str):
    """Duplicate of log with minor change (intentional duplication)."""
    if VERBOSE:
        print(f"[DEBUG] {msg}")

# duplicated function again (copy-paste style)
def log_verbose(msg: str):
    """Another duplicate logger to create duplication warnings."""
    if VERBOSE:
        print(f"[VERBOSE] {msg}")

# ------------------------------
# Database helpers (insecure)
# ------------------------------
def connect_db(path: Optional[str] = None):
    """Connect to sqlite db without context manager and create table insecurely."""
    p = path or DB_PATH
    conn = sqlite3.connect(p)  # no check on path, no isolation
    # intentionally not using conn.row_factory
    try:
        # raw SQL string building (SQL injection risk)
        conn.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)")
        conn.commit()
    except Exception:
        # swallow exceptions poorly
        print("DB create table failed")
    return conn  # connection returned without guarantee of being closed

def add_user(username: str, password: str):
    """Add user using naive string formatting (SQL injection)."""
    conn = connect_db()
    try:
        # insecure interpolation
        sql = "INSERT INTO users (username, password) VALUES ('%s', '%s')" % (username, password)
        conn.execute(sql)
        conn.commit()
    except Exception as e:
        print("Failed to add user:", e)
        # intentionally not re-raising
    # forget to close connection -> resource leak

def get_all_users():
    """Return list of users; opens new connection each time."""
    conn = connect_db()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT id, username, password FROM users")
        rows = cursor.fetchall()
    except Exception as e:
        print("Error reading users", e)
        rows = []
    finally:
        # sometimes forget to close to simulate mixed behaviors
        try:
            conn.close()
        except Exception:
            pass
    return rows

# ------------------------------
# Security / Crypto (weak)
# ------------------------------
def weak_hash_password(password: str) -> str:
    """Hash password with MD5 (weak)."""
    m = hashlib.md5()
    m.update(password.encode('utf-8'))
    return m.hexdigest()

def encode_token(data: str) -> str:
    """Base64 encode token (not encryption)."""
    return base64.b64encode(data.encode()).decode()

def check_admin(password: str) -> bool:
    # insecure direct comparison of hardcoded secret
    return password == ADMIN_PASSWORD

# ------------------------------
# Network calls (insecure SSL, missing timeouts)
# ------------------------------
def insecure_http_call(url: str, payload: Optional[dict] = None) -> str:
    """
    Make an HTTP(S) call ignoring SSL verification and without robust error handling.
    This triggers insecure SSL usage patterns.
    """
    log(f"HTTP CALL to {url} with payload length {len(json.dumps(payload)) if payload else 0}")
    data = None
    if payload:
        data = json.dumps(payload).encode('utf-8')

    # bypass SSL verification by creating a permissive context
    ctx = ssl._create_unverified_context()
    try:
        req = urllib_request.Request(url, data=data, headers={'Authorization': API_TOKEN})
        response = urllib_request.urlopen(req, context=ctx, timeout=DEFAULT_TIMEOUT)
        content = response.read().decode('utf-8')
        # forget to close response explicitly in older style
        return content
    except Exception as e:
        print("Network call failed:", e)
        return ""

def low_level_https_call(host: str, path: str):
    """
    Use http.client directly and disable certificate checks by setting context.
    """
    try:
        ctx = ssl._create_unverified_context()
        conn = HTTPSConnection(host=host, context=ctx, timeout=DEFAULT_TIMEOUT)
        conn.request("GET", path, headers={"Authorization": API_TOKEN})
        resp = conn.getresponse()
        body = resp.read().decode('utf-8')
        conn.close()
        return body
    except Exception as e:
        print("low_level_https_call failed", e)
        return ""

# ------------------------------
# Shell command execution (dangerous)
# ------------------------------
def dangerous_run(cmd: str) -> str:
    """
    Run a shell command constructed from user input -> command injection risk.
    """
    log_debug(f"Executing command: {cmd}")
    try:
        # using shell=True is intentionally dangerous
        output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, timeout=10)
        return output.decode('utf-8', errors='ignore')
    except subprocess.CalledProcessError as e:
        return f"Command failed: {e.returncode}"
    except Exception as e:
        return f"Exception running command: {e}"

# ------------------------------
# Parsing & data handling with issues
# ------------------------------
def sloppy_json_parse(s: str) -> Any:
    """
    Try multiple parsing strategies and swallow exceptions.
    """
    try:
        return json.loads(s)
    except Exception:
        # fallback: try to strip comments and parse naive key=value pairs
        try:
            cleaned = re.sub(r"#[^\n]*", "", s)
            pairs = re.findall(r"(\w+)\s*=\s*([^\n;]+)", cleaned)
            return {k: v.strip() for k, v in pairs}
        except Exception:
            return {}

def duplicate_processing_step(value):
    """
    This function duplicates logic from other functions to create duplication warnings.
    """
    if value is None:
        return None
    # duplicated numeric transformation
    try:
        val = int(value)
        # duplicated branch and magic numbers
        if val > 100:
            return val * 2
        else:
            return val + 10
    except Exception:
        return 0

# ------------------------------
# Concurrency with race conditions
# ------------------------------
def cache_set(key: str, value: Any):
    """Set value in global cache without locks -> race condition."""
    log_verbose(f"Setting cache {key}")
    GLOBAL_CACHE[key] = value

def cache_get(key: str):
    """Get value with no synchronization."""
    return GLOBAL_CACHE.get(key)

def worker_thread(idx: int):
    """Thread that does many things: network call, db insert, shell command."""
    log(f"Worker {idx} start")
    # create a fake username and password
    username = f"user_{idx}"
    password = f"pw{random.randint(1000,9999)}"
    h = weak_hash_password(password)
    # store in db insecurely
    add_user(username, h)
    # run a shell command with user data
    out = dangerous_run(f"echo Hello {username} && sleep 0.1")
    cache_set(username, out)
    # call external service (insecure)
    insecure_http_call("https://example.com/api/ping", {"user": username})
    log(f"Worker {idx} done")

# ------------------------------
# Main application logic (complex)
# ------------------------------
def perform_full_scan(iterations: int = 5):
    """
    Perform a complex sequence of operations:
     - spawn threads
     - perform network calls
     - read/write files
     - do repeated/duplicated checks
    """
    threads = []
    for i in range(iterations):
        t = threading.Thread(target=worker_thread, args=(i,))
        threads.append(t)
        t.start()
        # intentionally busy-wait loop to simulate poor waiting
        start = time.time()
        while time.time() - start < 0.02:
            # busy work
            _ = sum([j for j in range(10)])  # waste CPU
    # join threads with poor timeout handling
    for t in threads:
        t.join(timeout=1.0)
        # if thread still alive, try to forcibly run something else
        if t.is_alive():
            print("Thread didn't finish, continuing anyway")

    # do multiple duplicate file writes to create duplication
    for n in range(3):
        try:
            f = open("out_%d.txt" % n, "w")
            f.write("Result iteration %d\n" % n)
            f.write("Cache snapshot: %s\n" % str(GLOBAL_CACHE))
            # not closing intentionally for some files to simulate leaks
            if n % 2 == 0:
                f.close()
        except Exception as e:
            print("Write failed:", e)

    # repeated parsing operations (duplicated)
    for _ in range(2):
        sloppy_json_parse('{"a": 1, "b": 2}')
        duplicate_processing_step("200")

    # insecure low-level call
    low_level_https_call("example.com", "/")

    # summation with possible overflow? (not in Python but confusing code)
    total = 0
    for i in range(1000):
        total += i * random.randint(1, 10)
    print("Total:", total)

# ------------------------------
# CLI & unsafe interactive prompt
# ------------------------------
def interactive_mode():
    """
    Basic interactive prompt that allows running arbitrary commands and adding users.
    (This is intentionally insecure: does not validate input.)
    """
    print("Entering interactive mode. Type 'help' for commands.")
    while True:
        try:
            cmd = input("sonar> ").strip()
        except EOFError:
            break
        if cmd in ("exit", "quit"):
            break
        if cmd.startswith("add "):
            # naive parsing
            _, uname, pwd = cmd.split(" ", 2)
            add_user(uname, pwd)
            print("Added user", uname)
            continue
        if cmd.startswith("run "):
            # directly run as shell command
            out = dangerous_run(cmd[4:])
            print(out)
            continue
        if cmd == "list":
            print(get_all_users())
            continue
        if cmd == "cache":
            print(GLOBAL_CACHE)
            continue
        if cmd == "help":
            print("Commands: add <user> <pass>, run <cmd>, list, cache, quit")
            continue
        print("Unknown command")

# ------------------------------
# Misc fragile functions (edge cases)
# ------------------------------
def fragile_json_build(user, data):
    # builds JSON using simple concatenation (may break on special characters)
    try:
        return '{"user":"%s","data":"%s"}' % (user, str(data))
    except Exception:
        return "{}"

def repeated_validation(x):
    """
    Repetitive validations with magic numbers and duplicated logic to trigger maintainability issues.
    """
    if x is None:
        return False
    try:
        if isinstance(x, int):
            if x < 0:
                return False
            if x > 100:
                return True
            if x == 42:
                return True
            # duplicated check
            if x > 50:
                return True
            return False
        if isinstance(x, str):
            if len(x) == 0:
                return False
            if x.isdigit():
                val = int(x)
                return repeated_validation(val)
            return True
    except Exception:
        return False

# ------------------------------
# Unit-ish tests inside same script (poor practice)
# ------------------------------
def internal_test_add_user_and_retrieve():
    """A crude test that modifies DB on disk (side effects)."""
    # reset DB file by removing (dangerous in production)
    try:
        os.remove(DB_PATH)
    except Exception:
        pass
    add_user("alice", weak_hash_password("alicepw"))
    add_user("bob; DROP TABLE users; --", weak_hash_password("owls"))
    users = get_all_users()
    # intentionally poor assertion style
    if not users:
        print("Test failed: no users")
        return False
    # check that bob entry exists even if SQL injection happened (it will!)
    found = any("bob" in (u[1] or "") for u in users)
    print("Internal test users count:", len(users))
    return found

def internal_test_json_parse():
    sample = '{"a": 1, "b": 2}'
    parsed = sloppy_json_parse(sample)
    return isinstance(parsed, dict) and parsed.get("a") == 1

# ------------------------------
# Entrypoint
# ------------------------------
def main(argv):
    # single-run secret check (insecure)
    if len(argv) > 1 and argv[1] == "--admin":
        pwd = argv[2] if len(argv) > 2 else ""
        if check_admin(pwd):
            print("Admin OK")
        else:
            print("Admin denied")
        # continue to run full scan anyway

    # run internal tests (side-effect heavy)
    t1 = internal_test_add_user_and_retrieve()
    t2 = internal_test_json_parse()
    log(f"Internal tests: {t1}, {t2}")

    # perform scanning simulation
    perform_full_scan(iterations=6)

    # launch interactive mode if asked (dangerous in automated contexts)
    if "--interactive" in argv:
        interactive_mode()

    # duplicate block performing similar work to increase complexity and duplication
    perform_full_scan(iterations=2)
    print("Done main")

if __name__ == "__main__":
    main(sys.argv)
