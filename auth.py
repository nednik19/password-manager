from flask import Blueprint, render_template, request, redirect, url_for, session, flash, g, get_flashed_messages, jsonify
import sqlite3
import pyotp
import io
import base64
import os
import bcrypt
import qrcode
from PIL import Image
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from dotenv import load_dotenv
import hashlib

# Load environment variables
load_dotenv()

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

# Function to derive key from passkey
def derive_key_from_passkey(passkey, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(passkey.encode()))

# Generate a QR code for MFA setup
def generate_qr_code(username, secret_key):
    uri = pyotp.totp.TOTP(secret_key).provisioning_uri(name=username, issuer_name="Password Manager")
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    return img

# Encrypt a value using the provided passkey
def encrypt_with_passkey(secret_key, passkey, salt):
    derived_key = derive_key_from_passkey(passkey, salt)
    fernet = Fernet(derived_key)
    return fernet.encrypt(secret_key.encode()).decode()

# Decrypt a value using the provided passkey
def decrypt_with_passkey(encrypted_key, passkey, salt):
    try:
        derived_key = derive_key_from_passkey(passkey, salt)
        fernet = Fernet(derived_key)
        return fernet.decrypt(encrypted_key.encode()).decode()
    except InvalidToken:
        flash('Invalid passkey. Please try again.', 'error')
        return None

# Registration route
@auth.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()
        passkey = request.form.get('passkey', '').strip()

        if not username or not email or not password or not passkey:
            flash('All fields are required.', 'error')
            return render_template('register.html', messages=get_flashed_messages(with_categories=True))

        salt = os.urandom(16)
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        try:
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute("INSERT INTO users (username, email, password, salt) VALUES (?, ?, ?, ?)",
                           (username, email, hashed_password, salt))
            conn.commit()
        except sqlite3.IntegrityError:
            flash('Username or email already exists.', 'error')
            return render_template('register.html', messages=get_flashed_messages(with_categories=True))
        except sqlite3.OperationalError:
            flash('Database error occurred. Please try again later.', 'error')
            return render_template('register.html', messages=get_flashed_messages(with_categories=True))

        # Generate a TOTP secret key for MFA
        secret_key = pyotp.random_base32()
        encrypted_secret_key = encrypt_with_passkey(secret_key, passkey, salt)

        qr_image = generate_qr_code(username, secret_key)
        buffered = io.BytesIO()
        qr_image.save(buffered, format="PNG")
        qr_code_base64 = base64.b64encode(buffered.getvalue()).decode('utf-8')

        try:
            cursor.execute("UPDATE users SET secret_qrcode_key = ? WHERE username = ?", (encrypted_secret_key, username))
            conn.commit()
        except sqlite3.OperationalError:
            flash('Database error occurred while saving MFA information. Please try again later.', 'error')
            return render_template('register.html', messages=get_flashed_messages(with_categories=True))
        finally:
            conn.close()

        session['username'] = username
        session['passkey'] = passkey
        session['qr_code_base64'] = qr_code_base64
        session.modified = True

        return redirect(url_for('auth.register_MFA'))

    return render_template('register.html', messages=get_flashed_messages(with_categories=True))

# Register MFA route
@auth.route('/register_MFA', methods=['GET', 'POST'])
def register_MFA():
    username = session.get('username')
    if not username:
        flash('Session expired. Please log in again.', 'error')
        return redirect(url_for('auth.login'))

    qr_code_base64 = session.get('qr_code_base64')
    if not qr_code_base64:
        flash('QR code not found. Please try registering again.', 'error')
        return redirect(url_for('auth.register'))

    if request.method == 'POST':
        return redirect(url_for('auth.verify_otp'))

    return render_template('register_MFA.html', qr_code_base64=qr_code_base64, messages=get_flashed_messages(with_categories=True))

# Login route
@auth.route('/login', methods=['GET', 'POST'])
def login():
    print(request.form)
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        passkey = request.form.get('passkey', '').strip()

        if not username or not password or not passkey:
            flash('All fields are required.', 'error')
            return render_template('login.html', messages=get_flashed_messages(with_categories=True))

        conn = get_db()
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
            user = cursor.fetchone()

            if user is None or not bcrypt.checkpw(password.encode('utf-8'), user['password']):
                flash('Invalid username or password.', 'error')
                return render_template('login.html', messages=get_flashed_messages(with_categories=True))

            # Store passkey in session for later use
            session['username'] = username
            session['passkey'] = passkey
            session.modified = True
            return redirect(url_for('auth.verify_otp'))
        except sqlite3.OperationalError:
            flash('Database error occurred. Please try again later.', 'error')
        finally:
            conn.close()

    return render_template('login.html', messages=get_flashed_messages(with_categories=True))

# MFA Verification route
@auth.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    username = session.get('username')
    passkey = session.get('passkey')
    if not username:
        flash('Session expired. Please log in again.', 'error')
        return redirect(url_for('auth.login'))

    if request.method == 'POST':
        otp = request.form.get('otp', '').strip()

        print(passkey)

        if not otp:
            flash('OTP is required.', 'error')
            return render_template('verify_otp.html', messages=get_flashed_messages(with_categories=True))

        conn = get_db()
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT secret_qrcode_key, salt FROM users WHERE username = ?", (username,))
            user = cursor.fetchone()

            if user:
                encrypted_secret_key = user['secret_qrcode_key']
                salt = user['salt']
                secret_key = decrypt_with_passkey(encrypted_secret_key, passkey, salt)

                if secret_key is None:
                    return redirect(url_for('auth.verify_otp'))

                totp = pyotp.TOTP(secret_key)
                if totp.verify(otp):
                    return redirect(url_for('auth.dashboard'))
                else:
                    flash('Invalid OTP. Please try again.', 'error')
                    return render_template('verify_otp.html', messages=get_flashed_messages(with_categories=True))
            else:
                flash('User not found.', 'error')
                return redirect(url_for('auth.verify_otp'))
        except sqlite3.OperationalError:
            flash('Database error occurred. Please try again later.', 'error')
        finally:
            conn.close()

    return render_template('verify_otp.html', messages=get_flashed_messages(with_categories=True))

# Dashboard route
@auth.route('/dashboard', methods=['GET'])
def dashboard():
    username = session.get('username')
    passkey = session.get('passkey')

    if not username or not passkey:
        flash('Session expired. Please log in again.', 'error')
        return redirect(url_for('auth.login'))

    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM passwords WHERE user_id = (SELECT id FROM users WHERE username = ?)", (username,))
        passwords = cursor.fetchall()
        salt = cursor.execute("SELECT salt FROM users WHERE username = ?", (username,)).fetchone()['salt']

        passwords = [{
            'website': row['website'],
            'password': decrypt_with_passkey(row['password_encrypted'], passkey, salt)
        } for row in passwords]
    except sqlite3.OperationalError:
        flash('Database error occurred. Please try again later.', 'error')
        passwords = []
    finally:
        conn.close()

    return render_template('dashboard.html', passwords=passwords, messages=get_flashed_messages(with_categories=True))

# Add password route
@auth.route('/add_password', methods=['POST'])
def add_password():
    username = session.get('username')
    passkey = session.get('passkey')

    if not username or not passkey:
        flash('Session expired. Please log in again.', 'error')
        return redirect(url_for('auth.login'))

    site = request.form.get('site', '').strip()
    password = request.form.get('password', '').strip()

    if not site or not password:
        flash('All fields are required to add a password.', 'error')
        return redirect(url_for('auth.dashboard'))

    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT salt FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        if user is None:
            flash('User not found.', 'error')
            return redirect(url_for('auth.dashboard'))

        salt = user['salt']
        encrypted_password = encrypt_with_passkey(password, passkey, salt)

        cursor.execute("INSERT INTO passwords (user_id, website, password_encrypted) VALUES (?, ?, ?)",
                       (username, site, encrypted_password))
        conn.commit()
    except sqlite3.OperationalError as e:
        flash('Database error occurred. Please try again later.', 'error')
    finally:
        conn.close()

    flash('Password added successfully.', 'success')
    return redirect(url_for('auth.dashboard'))

# Encrypt a value using the provided passkey
def encrypt_with_passkey(secret_key, passkey, salt):
    derived_key = derive_key_from_passkey(passkey, salt)
    fernet = Fernet(derived_key)
    return fernet.encrypt(secret_key.encode()).decode()

# Decrypt a value using the provided passkey
def decrypt_with_passkey(encrypted_key, passkey, salt):
    try:
        derived_key = derive_key_from_passkey(passkey, salt)
        fernet = Fernet(derived_key)
        return fernet.decrypt(encrypted_key.encode()).decode()
    except InvalidToken:
        flash('Invalid passkey. Please try again.', 'error')
        return None

# API route to fetch passwords for JavaScript
@auth.route('/api/get_passwords', methods=['GET'])
def get_passwords():
    username = session.get('username')
    if not username:
        return jsonify({'error': 'Session expired. Please log in again.'}), 401

    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT salt FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        if user is None:
            return jsonify({'error': 'User not found.'}), 404

        salt = user['salt']
        passkey = session.get('passkey')

        cursor.execute("SELECT * FROM passwords WHERE user_id = ?", (username,))        
        passwords = cursor.fetchall()

        passwords_list = [{
            'website': row['website'],
            'password': decrypt_with_passkey(row['password_encrypted'], passkey, salt)
        } for row in passwords]
    except sqlite3.OperationalError as e:
        return jsonify({'error': 'Database error occurred. Please try again later.'}), 500
    finally:
        conn.close()

    return jsonify(passwords_list)

# Delete password route
@auth.route('/api/delete_password', methods=['POST'])
def delete_password():
    username = session.get('username')
    if not username:
        return jsonify({'error': 'Session expired. Please log in again.'}), 401

    site = request.json.get('site')
    if not site:
        return jsonify({'error': 'Website is required to delete a password.'}), 400

    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        if user is None:
            return jsonify({'error': 'User not found.'}), 404

        cursor.execute("DELETE FROM passwords WHERE user_id = ? AND website = ?", (username, site))
        conn.commit()

        if cursor.rowcount == 0:
            return jsonify({'error': 'Password not found.'}), 404

        return jsonify({'message': 'Password deleted successfully.'}), 200
    except sqlite3.OperationalError:
        return jsonify({'error': 'Database error occurred. Please try again later.'}), 500
    finally:
        conn.close()

@auth.route('/api/update_password', methods=['POST'])
def update_password():
    username = session.get('username')
    passkey = session.get('passkey')

    if not username or not passkey:
        return jsonify({'error': 'Session expired. Please log in again.'}), 401

    data = request.json
    site = data.get('site')
    new_password = data.get('new_password')

    if not site or not new_password:
        return jsonify({'error': 'Website and new password are required.'}), 400

    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT id, salt FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        if user is None:
            return jsonify({'error': 'User not found.'}), 404

        salt = user['salt']
        encrypted_password = encrypt_with_passkey(new_password, passkey, salt)

        cursor.execute("UPDATE passwords SET password_encrypted = ? WHERE user_id = ? AND website = ?", (encrypted_password, username, site))
        conn.commit()

        if cursor.rowcount == 0:
            return jsonify({'error': 'Password not found.'}), 404

        return jsonify({'message': 'Password updated successfully.'}), 200
    except sqlite3.OperationalError:
        return jsonify({'error': 'Database error occurred. Please try again later.'}), 500
    finally:
        conn.close()