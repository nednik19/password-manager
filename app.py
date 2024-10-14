from flask import Flask, redirect, url_for, session
from auth import auth
import os
from dotenv import load_dotenv
from datetime import timedelta

# Load environment variables from .env file
load_dotenv()

# Create a Flask application instance
app = Flask(__name__)

# Set secret key for session management
app.secret_key = os.getenv('SECRET_KEY')

# Set secure session cookie settings
app.config['SESSION_COOKIE_SECURE'] = True  # Only send cookies over HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access to cookies
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # Protect against CSRF

# Set session timeout (e.g., 30 minutes)
app.permanent_session_lifetime = timedelta(minutes=30)

# Register the authentication blueprint
app.register_blueprint(auth)

# Define a route for the home page that redirects to login
@app.route('/')
def home():
    return redirect(url_for('auth.login'))

# Main entry point for running the app
if __name__ == "__main__":
    # Load SSL certificate and key
    cert_file = os.getenv('SSL_CERT_FILE', 'server.crt')
    key_file = os.getenv('SSL_KEY_FILE', 'server.key')
    
    # Run the Flask app with SSL context
    app.run(host='127.0.0.1', port=5000, debug=True, ssl_context=(cert_file, key_file))