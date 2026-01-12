import os
import ssl
import yaml
import pickle
import hashlib
import sqlite3
import subprocess
from flask import Flask, request, redirect

app = Flask(__name__)

# --- SAST FINDING: Hardcoded Credentials ---
# Scanners like Bandit/Gitleaks should flag these immediately
DB_PASSWORD = "SuperSecretPassword123!"
API_KEY = "AKIA_FAKE_KEY_FOR_TESTING_PURPOSES"

# --- SAST FINDING: Insecure Configuration ---
# Debug mode being True is a major security risk in production
app.config['DEBUG'] = True

@app.route('/vulnerable-query')
def search_user():
    # --- SAST FINDING: SQL Injection (Taint Analysis) ---
    # User input (request.args) flows directly into a SQL query
    username = request.args.get('username')
    db = sqlite3.connect("users.db")
    cursor = db.cursor()
    
    # DANGER: String formatting in SQL queries
    query = "SELECT * FROM users WHERE name = '%s'" % username
    cursor.execute(query)
    return str(cursor.fetchall())

@app.route('/vulnerable-cmd')
def run_system_cmd():
    # --- SAST FINDING: Command Injection ---
    # User input flows into an OS command shell
    folder_name = request.args.get('folder')
    
    # DANGER: shell=True with user-controlled input
    command = f"ls -la {folder_name}"
    output = subprocess.check_output(command, shell=True)
    return output

@app.route('/vulnerable-redirect')
def open_redirect():
    # --- SAST FINDING: Open Redirect ---
    # Unvalidated user input used in a redirect
    target = request.args.get('url')
    return redirect(target)

def process_data(user_data):
    # --- SAST FINDING: Insecure Deserialization ---
    # pickle.loads can execute arbitrary code
    return pickle.loads(user_data)

def insecure_hashing(password):
    # --- SAST FINDING: Weak Hashing Algorithm ---
    # MD5 and SHA1 are cryptographically broken
    hasher = hashlib.md5()
    hasher.update(password.encode('utf-8'))
    return hasher.hexdigest()

def insecure_yaml_load(data):
    # --- SAST FINDING: Unsafe YAML Loading ---
    # yaml.load can instantiate arbitrary Python objects
    return yaml.load(data, Loader=yaml.Loader)

def weak_ssl_context():
    # --- SAST FINDING: Insecure TLS/SSL version ---
    # Using old protocols like TLSv1
    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
    return context

# --- Additional logic to reach 150+ lines ---
# This simulates "Legacy Code" noise that scanners have to parse

class LegacyDataHandler:
    def __init__(self, data_source):
        self.source = data_source
        self.buffer = []

    def load_buffer(self):
        # SAST: Potential Path Traversal if self.source is untrusted
        with open(self.source, 'r') as f:
            self.buffer = f.readlines()

    def transform_data(self):
        for i in range(len(self.buffer)):
            # Simulated complex logic
            self.buffer[i] = self.buffer[i].strip().upper()
            if "ADMIN" in self.buffer[i]:
                # SAST: Logging sensitive info or suspicious logic
                print(f"DEBUG: Admin record found: {self.buffer[i]}")

    def save_output(self, destination):
        # DANGER: chmod 777 makes files world-writable
        with open(destination, 'w') as f:
            f.write("\n".join(self.buffer))
        os.chmod(destination, 0o777)

def main():
    print("Starting Security Test Suite...")
    
    # Mock execution to trigger findings in some scanners
    try:
        handler = LegacyDataHandler("/etc/passwd")
        handler.load_buffer()
        handler.transform_data()
        
        # Triggering the weak hash
        print(f"Hash: {insecure_hashing('password123')}")
        
        # Triggering unsafe YAML
        bad_yaml = "!!python/object/apply:os.system ['ls']"
        insecure_yaml_load(bad_yaml)
        
    except Exception as e:
        print(f"Error during execution: {e}")

if __name__ == "__main__":
    main()

# [Padding logic to ensure scan depth]
# ... 
# (Adding dummy functions to simulate a real-world application)
def dummy_func_1(): pass
def dummy_func_2(): pass
# (Repeat as needed for line count)
# ...
