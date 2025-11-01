import os
import sqlite3
import requests
import subprocess
from flask import Flask, request, jsonify

app = Flask(__name__)

# --- SECURE PRACTICE: Load secrets from environment variables ---
# Avoids hardcoding secrets. The key should be set in the terminal.
app.config['SECRET_KEY'] = os.environ.get('APP_SECRET_KEY', 'default-key-for-dev')
API_KEY = os.environ.get('EXTERNAL_API_KEY')

def setup_database():
    """A helper function to set up a simple database for the example."""
    db = sqlite3.connect("safe_users.db")
    cursor = db.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, data TEXT)")
    # Check if user exists before inserting
    cursor.execute("SELECT * FROM users WHERE username = 'testuser'")
    if not cursor.fetchone():
        cursor.execute("INSERT INTO users (username, data) VALUES (?, ?)", ('testuser', 'Sample data'))
    db.commit()
    db.close()

@app.route("/user/<username>")
def get_user(username):
    """Retrieves user data from a database safely."""
    db = sqlite3.connect("safe_users.db")
    cursor = db.cursor()

    # --- SECURE PRACTICE: Use parameterized queries ---
    # This prevents SQL Injection. The '?' placeholder ensures user input
    # is treated as data, not as part of the SQL command.
    query = "SELECT * FROM users WHERE username = ?"
    cursor.execute(query, (username,))
    
    user_data = cursor.fetchone()
    db.close()

    if user_data:
        return jsonify(user_data)
    else:
        return "User not found.", 404

@app.route("/check-status")
def check_service_status():
    """Checks the status of a service using a safe subprocess call."""
    # --- SECURE PRACTICE: Use subprocess with a list of arguments ---
    # This avoids OS Command Injection. The command and its arguments
    # are passed as a list, so user input cannot create new commands.
    # We use a hardcoded, safe command for this example.
    try:
        result = subprocess.run(["ping", "-c", "1", "localhost"], capture_output=True, text=True, check=True)
        return f"Service is up:\n{result.stdout}", 200
    except subprocess.CalledProcessError as e:
        return f"Service check failed:\n{e.stderr}", 500

@app.route("/fetch-data")
def fetch_external_data():
    """Fetches data from an external API securely."""
    if not API_KEY:
        return "API key not configured.", 500
    
    try:
        # --- SECURE PRACTICE: Use timeouts and error handling for requests ---
        # This prevents the application from hanging indefinitely.
        response = requests.get("https://api.example.com/data", timeout=10)
        response.raise_for_status() # Checks for HTTP errors like 4xx or 5xx.
        return response.json()
    except requests.exceptions.RequestException as e:
        return f"Failed to fetch data: {e}", 503

if __name__ == "__main__":
    setup_database()
    # To run: pip install Flask requests
    # Set environment variables first:
    # export APP_SECRET_KEY='a_very_secret_key'
    # export EXTERNAL_API_KEY='another_secret'
    # app.run(debug=False) # debug=False is a secure practice for production
    pass