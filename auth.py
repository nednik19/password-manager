from flask import Blueprint, render_template, request, redirect, url_for, session, flash, g, get_flashed_messages, jsonify
import sqlite3
import pyotp
import io
import base64
import os
import bcrypt
import qrcode
from PIL import Image
from cryptography.fernet import Fernet
from dotenv import load_dotenv

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

# Registration route
@auth.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()

        if not username or not email or not password:
            flash('All fields are required.', 'error')
            return render_template('register.html', messages=get_flashed_messages(with_categories=True))

        salt = bcrypt.gensalt()
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)

        try:
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute("INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
                           (username, email, hashed_password))
            conn.commit()
        except sqlite3.IntegrityError as e:
            flash('Username or email already exists.', 'error')
            return render_template('register.html', messages=get_flashed_messages(with_categories=True))
        except sqlite3.OperationalError as e:
            flash('Database error occurred. Please try again later.', 'error')
            return render_template('register.html', messages=get_flashed_messages(with_categories=True))

        user_encryption_key = Fernet.generate_key().decode()
        try:
            cursor.execute("UPDATE users SET unique_key = ? WHERE username = ?", (user_encryption_key, username))
            conn.commit()
        except sqlite3.OperationalError as e:
            flash('Database error occurred while saving encryption key. Please try again later.', 'error')
            return render_template('register.html', messages=get_flashed_messages(with_categories=True))

        secret_key = pyotp.random_base32()
        qr_image = generate_qr_code(username, secret_key)
        buffered = io.BytesIO()
        qr_image.save(buffered, format="PNG")
        qr_code_base64 = base64.b64encode(buffered.getvalue()).decode('utf-8')

        try:
            cursor.execute("UPDATE users SET secret_qrcode_key = ? WHERE username = ?", (secret_key, username))
            conn.commit()
        except sqlite3.OperationalError as e:
            flash('Database error occurred while saving MFA information. Please try again later.', 'error')
            return render_template('register.html', messages=get_flashed_messages(with_categories=True))
        finally:
            conn.close()

        session['username'] = username
        session['qr_code_base64'] = qr_code_base64
        session.modified = True

        return render_template('register_MFA.html', qr_code_base64=qr_code_base64, messages=get_flashed_messages(with_categories=True))

    return render_template('register.html', messages=get_flashed_messages(with_categories=True))

# Login route
@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()

        if not username or not password:
            flash('All fields are required.', 'error')
            return render_template('login.html', messages=get_flashed_messages(with_categories=True))

        conn = get_db()
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
            user = cursor.fetchone()

            if user:
                hashed_password = user['password']
                if bcrypt.checkpw(password.encode('utf-8'), hashed_password):
                    session['username'] = username
                    session.modified = True
                    return redirect(url_for('auth.verify_otp'))
                else:
                    flash('Invalid password. Please try again.', 'error')
            else:
                flash('Username not found.', 'error')
        except sqlite3.OperationalError as e:
            flash('Database error occurred. Please try again later.', 'error')
        finally:
            conn.close()

    return render_template('login.html', messages=get_flashed_messages(with_categories=True))

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

# MFA Verification route
@auth.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    username = session.get('username')
    if not username:
        flash('Session expired. Please log in again.', 'error')
        return redirect(url_for('auth.login'))

    if request.method == 'POST':
        otp = request.form.get('otp', '').strip()

        if not otp:
            flash('OTP is required.', 'error')
            return render_template('verify_otp.html', messages=get_flashed_messages(with_categories=True))

        conn = get_db()
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT secret_qrcode_key FROM users WHERE username = ?", (username,))
            user = cursor.fetchone()

            if user:
                secret_key = user['secret_qrcode_key']
                totp = pyotp.TOTP(secret_key)
                if totp.verify(otp):
                    return redirect(url_for('auth.dashboard'))
                else:
                    flash('Invalid OTP. Please try again.', 'error')
                    return render_template('verify_otp.html', messages=get_flashed_messages(with_categories=True))
            else:
                flash('User not found.', 'error')
                return redirect(url_for('auth.verify_otp'))
        except sqlite3.OperationalError as e:
            flash('Database error occurred. Please try again later.', 'error')
        finally:
            conn.close()

    return render_template('verify_otp.html', messages=get_flashed_messages(with_categories=True))

# Dashboard route
@auth.route('/dashboard', methods=['GET'])
def dashboard():
    username = session.get('username')
    if not username:
        flash('Session expired. Please log in again.', 'error')
        return redirect(url_for('auth.login'))

    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM passwords WHERE user_id = (SELECT id FROM users WHERE username = ?)", (username,))
        passwords = cursor.fetchall()
        user_encryption_key = cursor.execute("SELECT unique_key FROM users WHERE username = ?", (username,)).fetchone()['unique_key']
        fernet = Fernet(user_encryption_key.encode())
        passwords = [{
            'website': row['website'],
            'username': row['username'],
            'password': fernet.decrypt(row['password'].encode()).decode()
        } for row in passwords]
    except sqlite3.OperationalError as e:
        flash('Database error occurred. Please try again later.', 'error')
        passwords = []
    finally:
        conn.close()

    return render_template('dashboard.html', passwords=passwords, messages=get_flashed_messages(with_categories=True))

# Add password route
@auth.route('/add_password', methods=['POST'])
def add_password():
    username = session.get('username')
    if not username:
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
        cursor.execute("SELECT unique_key FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        if user is None:
            flash('User not found.', 'error')
            return redirect(url_for('auth.dashboard'))

        user_encryption_key = user['unique_key']
        fernet = Fernet(user_encryption_key.encode())

        encrypted_password = fernet.encrypt(password.encode()).decode()

        cursor.execute("INSERT INTO passwords (user_id, website, password_encrypted) VALUES (?, ?, ?)",
                       (username, site, encrypted_password))
        conn.commit()
    except sqlite3.OperationalError as e:
        flash('Database error occurred. Please try again later.', 'error')
    finally:
        conn.close()

    flash('Password added successfully.', 'success')
    return redirect(url_for('auth.dashboard'))


# Function to encrypt a password
def encrypt_password(password: str, encryption_key: str) -> str:
    fernet = Fernet(encryption_key.encode())
    return fernet.encrypt(password.encode()).decode()

# Function to decrypt a password
def decrypt_password(encrypted_password: str, encryption_key: str) -> str:
    fernet = Fernet(encryption_key.encode())
    return fernet.decrypt(encrypted_password.encode()).decode()

# API route to fetch passwords for JavaScript
@auth.route('/api/get_passwords', methods=['GET'])
def get_passwords():
    username = session.get('username')
    if not username:
        return jsonify({'error': 'Session expired. Please log in again.'}), 401

    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT unique_key FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        if user is None:
            return jsonify({'error': 'User not found.'}), 404

        user_encryption_key = user['unique_key']
        fernet = Fernet(user_encryption_key.encode())

        cursor.execute("SELECT * FROM passwords WHERE user_id = ?", (username,))
        passwords = cursor.fetchall()

        passwords_list = [{
            'website': row['website'],
            'password': fernet.decrypt(row['password_encrypted']).decode()
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
    if not username:
        return jsonify({'error': 'Session expired. Please log in again.'}), 401

    data = request.json
    site = data.get('site')
    new_password = data.get('new_password')

    if not site or not new_password:
        return jsonify({'error': 'Website and new password are required.'}), 400

    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        if user is None:
            return jsonify({'error': 'User not found.'}), 404

        user_encryption_key = cursor.execute("SELECT unique_key FROM users WHERE username = ?", (username,)).fetchone()['unique_key']
        fernet = Fernet(user_encryption_key.encode())

        encrypted_password = fernet.encrypt(new_password.encode()).decode()

        cursor.execute("UPDATE passwords SET password_encrypted = ? WHERE user_id = ? AND website = ?", (encrypted_password, username, site))
        conn.commit()

        if cursor.rowcount == 0:
            return jsonify({'error': 'Password not found.'}), 404

        return jsonify({'message': 'Password updated successfully.'}), 200
    except sqlite3.OperationalError:
        return jsonify({'error': 'Database error occurred. Please try again later.'}), 500
    finally:
        conn.close()
