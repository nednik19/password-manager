from flask import Flask, redirect, url_for
from auth import auth
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Create a Flask application instance
app = Flask(__name__)

# Set secret key for session management
app.secret_key = os.getenv('SECRET_KEY')

# Register the authentication blueprint
app.register_blueprint(auth)

# Define a route for the home page that redirects to login
@app.route('/')
def home():
    return redirect(url_for('auth.login'))

# Main entry point for running the app
if __name__ == "__main__":
    app.run(debug=True)