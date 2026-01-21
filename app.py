from flask import Flask, render_template, request, redirect, url_for, session, flash
import re
import os
import logging
from datetime import datetime, timedelta, date
from dateutil.relativedelta import relativedelta
import requests
import bcrypt

# -------------------- App Config --------------------
app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'dev_fallback_key')

API_URL = 'https://w23012928.nuwebspace.co.uk/apityneside/users'

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# -------------------- Validation Helpers --------------------
def is_valid_email(email):
    return re.match(r"[^@]+@[^@]+\.[^@]+", email)

def is_valid_phone(phone):
    return re.match(r"^(?:\+44|0)7\d{9}$", phone)

def is_strong_password(password):
    return (
        len(password) >= 8 and
        re.search(r"[A-Z]", password) and
        re.search(r"[a-z]", password) and
        re.search(r"\d", password) and
        re.search(r"[!@#$%^&*(),.?\":{}|<>]", password)
    )

def is_old_enough(dob_str):
    try:
        dob = datetime.strptime(dob_str, "%d/%m/%Y").date()
        today = date.today()
        age = today.year - dob.year - ((today.month, today.day) < (dob.month, dob.day))
        return True
    except ValueError:
        return False

# -------------------- Routes --------------------
@app.route('/')
def home():
    if 'user' in session:
        return render_template('home.html', user=session['user'])
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '').strip()

        if not email or not password:
            flash("Please provide both email and password.", "warning")
            return render_template('login.html')

        try:
            response = requests.get(API_URL)
            response.raise_for_status()
            users = response.json()
        except Exception as e:
            logger.error(f"Error accessing user data: {e}")
            flash("Something went wrong accessing user data.", "danger")
            return render_template('login.html')

        user = next((u for u in users if u['email'].lower() == email), None)

        if user:
            stored_hash = user.get('password_hash', '')
            try:
                stored_hash = user.get('password_hash', '').replace('$2y$', '$2b$')
                if bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8')):
                    session['user'] = {
                        "first_name": user['first_name'],
                        "last_name": user['last_name'],
                        "email": user['email'],
                        "user_id": user['user_id']
                    }
                    flash("Logged in successfully.", "success")
                    return redirect(url_for('home'))
                else:
                    flash("Invalid email or password.", "danger")
            except Exception as e:
                logger.exception("Password hash verification failed.")
                flash("Error during login.", "danger")
        else:
            flash("Invalid email or password.", "danger")

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        first_name = request.form.get('first_name', '').strip()
        last_name = request.form.get('last_name', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        phone = request.form.get('phone', '').strip()
        dob = request.form.get('dob', '')

        errors = []

        # Validations
        if not all([first_name, last_name, email, password, dob]):
            errors.append("All fields are required.")

        elif not is_valid_email(email):
            errors.append("Invalid email address.")

        elif not is_strong_password(password):
            errors.append("Your password does not match all the required feilds.")

        elif phone and not is_valid_phone(phone):
            errors.append("Invalid phone number. must start with +44/ 07.")

        elif not is_old_enough(dob):
            errors.append("You must be at least 13 years old to register.")

        if errors:
            for error in errors:
                flash(error, 'danger')
            return render_template('register.html', form=request.form, max_dob=get_max_dob())

        try:
            # Check if the email is already registered
            existing_users = requests.get(API_URL).json()
            if any(u['email'].lower() == email for u in existing_users):
                flash("Email already registered.", "danger")
            else:
                hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
                hashed_password_str = hashed_password.decode('utf-8')
                logger.info("Hash being sent to API:", hashed_password_str)

                # Register user
                payload = {
                    'first_name': first_name,
                    'last_name': last_name,
                    'email': email,
                    'password': hashed_password_str,
                    'phone_number': phone,
                    'date_of_birth': dob
                }
                post_response = requests.post(API_URL, json=payload)
                if post_response.status_code == 201:
                    flash("Registration successful! Please log in.", "success")
                    return redirect(url_for('login'))
                else:
                    logger.error(f"API registration failed: {post_response.text}")
                    flash("Registration failed. Try again later.", "danger")
        except Exception as e:
            logger.exception("Error during registration.")
            flash("Error during registration. Please try again later.", "danger")

    return render_template('register.html', form={}, max_dob=get_max_dob())

def get_max_dob():
    return date.today().replace(year=date.today().year - 13).strftime('%Y/%m/%d')

@app.route('/logout')
def logout():
    session.pop('user', None)
    flash("Logged out.", "info")
    return redirect(url_for('login'))

# -------------------- Main --------------------
if __name__ == '__main__':
    app.run(debug=True)
