from flask import Blueprint, render_template, request, redirect, url_for, session, flash, g, get_flashed_messages
import sqlite3
import pyotp
import io
import base64
import os
import bcrypt  # Import bcrypt for password hashing
import qrcode
from PIL import Image

# Define the authentication blueprint
auth = Blueprint('auth', __name__)

# Connect to the database
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect('DB/database.db')
        g.db.row_factory = sqlite3.Row
    return g.db

# Close the database connection when the request ends
@auth.teardown_request
def close_db(exception):
    db = g.pop('db', None)
    if db is not None:
        db.close()

# Generate a QR code for MFA setup
def generate_qr_code(username, secret_key):
    # Generate the TOTP URI
    uri = pyotp.totp.TOTP(secret_key).provisioning_uri(name=username, issuer_name="Password Manager")
    
    # Generate the QR code image
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(uri)
    qr.make(fit=True)

    # Save the QR code as an image
    img = qr.make_image(fill_color="black", back_color="white")
    return img

# Registration route
@auth.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Get user input from the registration form
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()

        # Debugging logs for form data
        print(f"Received form data - Username: '{username}', Email: '{email}', Password: '{password}'")

        # Validate form fields
        if not username or not email or not password:
            flash('All fields are required.', 'error')
            return render_template('register.html', messages=get_flashed_messages(with_categories=True))

        # Generate a salt and hash the password using bcrypt
        salt = bcrypt.gensalt()
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)

        try:
            # Explicitly manage the database connection
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute("INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
                           (username, email, hashed_password))
            conn.commit()
        except sqlite3.OperationalError as e:
            flash('Database error occurred. Please try again later.', 'error')
            print(f"Database error: {e}")  # Debugging log for database errors
            return render_template('register.html', messages=get_flashed_messages(with_categories=True))

        # Generate a QR code for Multi-Factor Authentication (MFA) setup
        secret_key = pyotp.random_base32()  # Generate a random base32 secret key
        qr_image = generate_qr_code(username, secret_key)  # Create a QR code image
        buffered = io.BytesIO()
        qr_image.save(buffered, format="PNG")
        qr_code_base64 = base64.b64encode(buffered.getvalue()).decode('utf-8')

        try:
            # Save the secret key to the database for future OTP verification
            cursor.execute("UPDATE users SET secret_qrcode_key = ? WHERE username = ?", (secret_key, username))
            conn.commit()
        except sqlite3.OperationalError as e:
            flash('Database error occurred while saving MFA information. Please try again later.', 'error')
            print(f"Database error while saving MFA info: {e}")  # Debugging log for database errors
            return render_template('register.html', messages=get_flashed_messages(with_categories=True))

        # Store the username and QR code in the session for use during OTP verification
        session['username'] = username
        session['qr_code_base64'] = qr_code_base64
        session.modified = True  # Ensure session is saved

        # Debugging log for MFA setup
        print(f"MFA setup complete for user: '{username}' with secret key: '{secret_key}'")

        # Pass the QR code as a base64 string to the template
        return render_template('register_MFA.html', qr_code_base64=qr_code_base64, messages=get_flashed_messages(with_categories=True))

    # Render the registration form
    return render_template('register.html', messages=get_flashed_messages(with_categories=True))

# Login route
@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Get user input from the login form
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()

        # Debugging logs for form data
        print(f"Received login data - Username: '{username}', Password: '{password}'")

        # Validate form fields
        if not username or not password:
            flash('All fields are required.', 'error')
            return render_template('login.html', messages=get_flashed_messages(with_categories=True))

        # Retrieve the user from the database using the provided username
        try:
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
            user = cursor.fetchone()
        except sqlite3.OperationalError as e:
            flash('Database error occurred. Please try again later.', 'error')
            print(f"Database error: {e}")
            return render_template('login.html', messages=get_flashed_messages(with_categories=True))

        if user:
            # Retrieve the hashed password from the database
            hashed_password = user['password']

            # Verify the provided password with the stored hashed password using bcrypt
            if bcrypt.checkpw(password.encode('utf-8'), hashed_password):
                # Set session data for the logged-in user
                session['username'] = username
                session.modified = True  # Ensure session is saved
                # Debugging log for successful login
                print(f"Login successful for user: '{username}'")
                # Redirect to OTP verification for MFA
                return redirect(url_for('auth.verify_otp'))
            else:
                # If the password is incorrect, flash an error message
                flash('Invalid password. Please try again.', 'error')
                print(f"Invalid password for user: '{username}'")
        else:
            # If the username is not found, flash an error message
            flash('Username not found.', 'error')
            print(f"Username not found: '{username}'")

        conn.close()

    # Render the login form
    return render_template('login.html', messages=get_flashed_messages(with_categories=True))

# MFA Registration route
@auth.route('/register_MFA', methods=['GET', 'POST'])
def register_MFA():
    # Get the username from the session
    username = session.get('username')
    qr_code_base64 = session.get('qr_code_base64')

    if not username:
        flash('Session expired. Please log in again.', 'error')
        return redirect(url_for('auth.login'))

    if request.method == 'POST':
        # Get the OTP entered by the user
        otp = request.form.get('otp', '').strip()

        # Debugging log for OTP input
        print(f"Received OTP: '{otp}' for user: '{username}'")

        # Validate OTP field
        if not otp:
            flash('OTP is required.', 'error')
            return render_template('register_MFA.html', qr_code_base64=qr_code_base64, messages=get_flashed_messages(with_categories=True))

        # Retrieve the secret key for the user from the database
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT secret_qrcode_key FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()

        if user:
            secret_key = user['secret_qrcode_key']
            # Debugging log for secret key retrieval
            print(f"Retrieved secret key for user '{username}': '{secret_key}'")
            # Create a TOTP object using the secret key
            totp = pyotp.TOTP(secret_key)
            # Verify the OTP entered by the user
            if totp.verify(otp):
                # OTP verification successful, redirect to the home page
                print(f"OTP verification successful for user '{username}'")
                conn.close()
                return redirect(url_for('index'))
            else:
                # If OTP verification fails, flash an error message
                flash('Invalid OTP. Please try again.', 'error')
                print(f"OTP verification failed for user '{username}' with OTP '{otp}'")
                conn.close()
                return render_template('register_MFA.html', qr_code_base64=qr_code_base64, messages=get_flashed_messages(with_categories=True))
        else:
            flash('User not found.', 'error')
            print(f"User not found during MFA setup for username '{username}'")
            conn.close()
            return redirect(url_for('auth.register_MFA'))

    # Render the MFA registration form
    return render_template('register_MFA.html', qr_code_base64=qr_code_base64, messages=get_flashed_messages(with_categories=True))

# OTP Verification route
@auth.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    # Get the username from the session
    username = session.get('username')

    if not username:
        flash('Session expired. Please log in again.', 'error')
        return redirect(url_for('auth.login'))

    if request.method == 'POST':
        # Get the OTP entered by the user
        otp = request.form.get('otp', '').strip()

        # Debugging log for OTP input
        print(f"Received OTP for verification: '{otp}' for user: '{username}'")

        # Validate OTP field
        if not otp:
            flash('OTP is required.', 'error')
            return render_template('verify_otp.html', messages=get_flashed_messages(with_categories=True))

        # Retrieve the secret key for the user from the database
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT secret_qrcode_key FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()

        if user:
            secret_key = user['secret_qrcode_key']
            # Debugging log for secret key retrieval
            print(f"Retrieved secret key for user '{username}': '{secret_key}'")
            # Create a TOTP object using the secret key
            totp = pyotp.TOTP(secret_key)
            # Verify the OTP entered by the user
            if totp.verify(otp):
                # OTP verification successful, redirect to the home page
                print(f"OTP verification successful for user '{username}'")
                conn.close()
                return redirect(url_for('auth.login'))
            else:
                # If OTP verification fails, flash an error message
                flash('Invalid OTP. Please try again.', 'error')
                print(f"OTP verification failed for user '{username}' with OTP '{otp}'")
                conn.close()
                return render_template('verify_otp.html', messages=get_flashed_messages(with_categories=True))
        else:
            flash('User not found.', 'error')
            print(f"User not found during OTP verification for username '{username}'")
            conn.close()
            return redirect(url_for('auth.verify_otp'))

    # Render the OTP verification form
    return render_template('verify_otp.html', messages=get_flashed_messages(with_categories=True))