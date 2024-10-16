# Password Manager

## Overview
This project is a web-based Password Manager built using Flask, JavaScript, HTML, and CSS. The application provides secure password management features, including user registration, multi-factor authentication (MFA), and encrypted storage of credentials.

![Password-manager](images/show.gif)

## Features
- **User Registration and Login**: Secure user registration and login system with support for multi-factor authentication (MFA).
- **OTP Verification**: Implements one-time password (OTP) verification for enhanced security.
- **Dashboard**: User-friendly dashboard to manage stored passwords.
- **Secure Storage**: Uses encryption for secure storage of passwords.
- **Certificate Generation**: Ability to generate security certificates for secure communication.

## Installation
1. **Clone the repository**:
   ```bash
   git clone <repository-url>
   cd password-manager
   ```

2. **Create a virtual environment**:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows use `venv\Scripts\activate`
   ```

3. **Install the dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Create the database**:
   Run the following command to create the necessary database:
   ```bash
   python create_db.py
   ```

## Usage
1. **Run the application**:
   ```bash
   python app.py
   ```

2. **Access the web interface**:
   Open a web browser and navigate to `http://127.0.0.1:5000`.

## Project Structure
- `app.py`: Main entry point for the Flask application.
- `auth.py`: Handles user authentication, including login, registration, and OTP verification.
- `generate_cert.py`: Generates security certificates for secure communication.
- `create_db.py`: Initializes the database for storing user credentials.
- `static/`: Contains static files (CSS, JavaScript).
  - `styles.css`, `style.css`: Styling for the web pages.
  - `script.js`: JavaScript for client-side interactions.
- `templates/`: HTML templates for different pages.
  - `base.html`: Base layout used by other pages.
  - `register.html`, `login.html`, `dashboard.html`, etc.: Individual pages for user interactions.

## Dependencies
- **Flask**: Web framework used for building the application.
- **SQLite**: Database used for storing user credentials.
- **Other Python Packages**: Listed in `requirements.txt`.

## Security
- User passwords are encrypted before being stored in the database.
- Implements multi-factor authentication (MFA) for enhanced security.
- Uses HTTPS certificates for secure communication.

## Contributing
Feel free to open issues or submit pull requests for improvements.

## License
This project is licensed under the MIT License.

