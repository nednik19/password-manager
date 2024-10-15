from flask import Flask, redirect, url_for, session, render_template
from auth import auth, limiter  # Import auth and limiter from auth.py
import os
from dotenv import load_dotenv
from datetime import timedelta
from flask_wtf.csrf import CSRFProtect

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

# Initialize CSRF protection
csrf = CSRFProtect(app)

# Apply the rate limiter globally
limiter.init_app(app)

# Register the authentication blueprint
app.register_blueprint(auth)

# Define a route for the home page that redirects to login
@app.route('/')
def home():
    return redirect(url_for('auth.login'))

# Add error handlers for specific HTTP error codes
@app.errorhandler(401)
def unauthorized_error(error):
    app.logger.error(f"401 Unauthorized - You are not authorized to access this page. {str(error)}")

    error = "401 Unauthorized - You are not authorized to access this page."
    return render_template('error.html', error=error), 401

@app.errorhandler(403)
def forbidden_error(error):
    app.logger.error(f"403 Forbidden - You don't have permission to access this page. {str(error)}")    

    error = "403 Forbidden - You don't have permission to access this page."
    return render_template('error.html', error=error), 403

@app.errorhandler(404)
def not_found_error(error):
    app.logger.error(f"404 - Page not found. {str(error)}")    

    error = "404 - Page not found."
    return render_template('error.html', error=error), 404

@app.errorhandler(405)
def method_not_allowed_error(error):
    # Log the error
    app.logger.error(f"Method Not Allowed error occurred: {str(error)}")
    
    # Display a user-friendly error message
    error = "The method is not allowed for the requested URL."
    return render_template('error.html', error=error), 405

@app.errorhandler(429)
def method_not_allowed_error(error):
    # Log the error
    app.logger.error(f"Too many request: {str(error)}")
    
    # Display a user-friendly error message
    error = "Too many requests."
    return render_template('error.html', error=error), 429

@app.errorhandler(500)
def internal_error(error):
    app.logger.error(f"Internal Server error. {str(error)}")

    error = "Internal Server Error"
    return render_template('error.html', error=error), 500


# Main entry point for running the app
if __name__ == "__main__":
    # Load SSL certificate and key
    cert_file = os.getenv('SSL_CERT_FILE', 'server.crt')
    key_file = os.getenv('SSL_KEY_FILE', 'server.key')
    
    # Run the Flask app with SSL context
    app.run(host='127.0.0.1', port=5000, debug=True, ssl_context=(cert_file, key_file))
