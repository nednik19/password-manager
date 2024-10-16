import sqlite3
import os

# Define the path for the database
DB_FOLDER = 'DB'
DB_PATH = os.path.join(DB_FOLDER, 'database.db')

# Ensure the DB folder exists
os.makedirs(DB_FOLDER, exist_ok=True)

# Connect to the SQLite database
conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()

# Create the 'users' table
cursor.execute('''
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password BLOB NOT NULL,
    email TEXT UNIQUE NOT NULL,
    secret_qrcode_key TEXT,
    salt TEXT
)
''')

# Commit the changes and close the connection
conn.commit()
conn.close()

# Connect to the SQLite database
conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()

# Create the 'users' table
cursor.execute('''
CREATE TABLE passwords (
    user_id INTEGER NOT NULL,
    website TEXT NOT NULL,
    password_encrypted BLOB NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id)
)
''')

# Commit the changes and close the connection
conn.commit()
conn.close()

# Connect to the SQLite database
conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()

# Create the 'users' table
cursor.execute('''
CREATE TABLE user_login_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    failed_attempts INTEGER DEFAULT 0,
    lock_until DATETIME,
    FOREIGN KEY (user_id) REFERENCES users(id)
)
''')

# Commit the changes and close the connection
conn.commit()
conn.close()




print(f"Database created successfully at {DB_PATH} with 'users' table.")