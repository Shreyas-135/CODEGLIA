import os
import sqlite3
from flask import Flask, request, jsonify

app = Flask(__name__)

# --- VULNERABILITY 1: Hardcoded Secret ---
# A real API key is embedded directly in the code.
app.config['SECRET_KEY'] = 'sk-proj-abc123def456ghi789jkl'

@app.route("/lookup")
def dns_lookup():
    """Takes a hostname from a query parameter and looks it up."""
    hostname = request.args.get("hostname")
    if not hostname:
        return "Please provide a hostname.", 400

    # --- VULNERABILITY 2: OS Command Injection ---
    # The user's input is passed directly to a shell command.
    # An attacker can use input like "google.com; rm -rf /" to run arbitrary commands.
    command = f"nslookup {hostname}"
    os.system(command)
    
    return f"Executed lookup for {hostname}", 200

@app.route("/user/<username>")
def get_user(username):
    """Retrieves user data from a database."""
    db = sqlite3.connect("users.db")
    cursor = db.cursor()

    # --- VULNERABILITY 3: SQL Injection ---
    # The username is formatted directly into the SQL query.
    # An attacker can use a username like "' OR 1=1 --" to dump all user data.
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
    
    user_data = cursor.fetchone()
    db.close()

    if user_data:
        return jsonify(user_data)
    else:
        return "User not found.", 404

if __name__ == "__main__":
    # This part is for running the app, but is not needed for scanning.
    # To run: pip install Flask
    # app.run(debug=True)
    pass