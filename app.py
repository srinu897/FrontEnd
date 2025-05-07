from flask import Flask, render_template, request, redirect, session, url_for, flash, make_response
import pymysql
from flask_mail import Mail, Message
import random
import string
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Configure Flask-Mail
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'samalasrinivas554@gmail.com'
app.config['MAIL_PASSWORD'] = 'aopv nbhl lvnk uxzb'  # App password
app.config['MAIL_DEFAULT_SENDER'] = 'samalasrinivas554@gmail.com'

mail = Mail(app)

# MySQL connection
connection = pymysql.connect(
    host='localhost',
    user='root',
    password='root',
    database='flask_auth',
    cursorclass=pymysql.cursors.DictCursor
)

def nocache(view):
    @wraps(view)
    def no_cache(*args, **kwargs):
        response = make_response(view(*args, **kwargs))
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '-1'
        return response
    return no_cache

@app.route('/')
def index():
    if 'username' in session:
        return redirect(url_for('home'))
    return redirect(url_for('login'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        hashed_password = generate_password_hash(password)

        with connection.cursor() as cursor:
            cursor.execute("SELECT * FROM users WHERE username=%s OR email=%s", (username, email))
            existing_user = cursor.fetchone()
            if existing_user:
                return "User with this username or email already exists!"
            cursor.execute("INSERT INTO users (username, email, password) VALUES (%s, %s, %s)",
                           (username, email, hashed_password))
            connection.commit()
        return redirect(url_for('login'))

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'username' in session:
        return redirect(url_for('home'))

    error = None
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        with connection.cursor() as cursor:
            cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
            user = cursor.fetchone()

            if user and check_password_hash(user['password'], password):
                session['username'] = user['username']
                return redirect(url_for('home'))
            else:
                error = "Invalid email or password. Please try again."

    response = make_response(render_template('login.html', error=error))
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '-1'
    return response

@app.route('/home')
def home():
    if 'username' not in session:
        return redirect(url_for('login'))

    response = make_response(render_template('home.html', username=session['username']))
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '-1'
    return response

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        with connection.cursor() as cursor:
            cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
            user = cursor.fetchone()
            if user:
                otp = ''.join(random.choices(string.digits, k=6))
                cursor.execute("UPDATE users SET otp=%s WHERE email=%s", (otp, email))
                connection.commit()

                session['reset_email'] = email

                message = Message("OTP for Password Reset", recipients=[email])
                message.body = f"Your OTP for password reset is: {otp}"

                try:
                    mail.send(message)
                    flash('An OTP has been sent to your email.', 'info')
                    return redirect(url_for('verify_otp'))
                except Exception as e:
                    print(f"Email error: {e}")
                    flash('Error sending OTP. Try again later.', 'danger')
            else:
                flash('Email not found.', 'danger')

    return render_template('forgot_password.html')

@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    if request.method == 'POST':
        entered_otp = request.form['otp']
        email = session.get('reset_email')
        if not email:
            flash('Session expired. Please try again.', 'danger')
            return redirect(url_for('forgot_password'))

        with connection.cursor() as cursor:
            cursor.execute("SELECT otp FROM users WHERE email=%s", (email,))
            user = cursor.fetchone()

            if user and user['otp'] == entered_otp:
                return redirect(url_for('reset_password'))
            else:
                flash('Invalid OTP. Please try again.', 'danger')

    return render_template('verify_otp.html')

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    email = session.get('reset_email')
    if not email:
        flash('Session expired. Please try again.', 'danger')
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        new_password = request.form['password']
        hashed_password = generate_password_hash(new_password)

        with connection.cursor() as cursor:
            cursor.execute("UPDATE users SET password=%s, otp=NULL WHERE email=%s",
                           (hashed_password, email))
            connection.commit()
            session.pop('reset_email', None)
            flash('Password reset successful!', 'success')
            return redirect(url_for('login'))

    return render_template('reset_password.html')

if __name__ == '__main__':
    app.run(debug=True)