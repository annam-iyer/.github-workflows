import sqlite3
from flask import Flask, request

app = Flask(__name__)

# --- SECRET SCANNING TRIGGER ---
# This mimics a high-entropy "canary" token that GitHub scanners detect.
# Using a 'p8e-' prefix is a common pattern for Adobe/Partner tokens.
ADOBE_MOCK_TOKEN = "p8e-testing-token-detected-by-github-123456789"

# --- SAST (CODE SCANNING) TRIGGER ---
# This function is intentionally vulnerable to SQL Injection (CWE-89).
# GitHub CodeQL will flag the use of f-strings in a cursor.execute() call.
def get_user_data(username):
    db = sqlite3.connect("users.db")
    cursor = db.cursor()
    
    # VULNERABILITY: User input is directly concatenated into the query.
    # An attacker could input: admin' OR '1'='1
    query = f"SELECT * FROM users WHERE username = '{username}'"
    
    try:
        cursor.execute(query)
        return cursor.fetchone()
    except Exception as e:
        return str(e)
    finally:
        db.close()

@app.route("/user")
def user_profile():
    # Grabbing input from a URL parameter
    user_input = request.args.get('name', '')
    
    # Passing 'tainted' data to the vulnerable function
    profile = get_user_data(user_input)
    
    return f"Profile Data: {profile}"

@app.route("/")
def index():
    # Hardcoded credentials trigger 'Hardcoded Secret' SAST alerts too
    admin_creds = {"user": "admin", "pass": "Password123!"}
    return "Application is running."

if __name__ == "__main__":
    # Insecurely running with debug=True (another common SAST finding)
    app.run(debug=True, port=5000)
