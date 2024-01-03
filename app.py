import os
import datetime

from cs50 import SQL
from flask import Flask, render_template, request, redirect, url_for, session, login_user
from flask_session import Session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
# Import other necessary modules and functions

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////tmp/test.db'  # Or other database URI
db = SQLAlchemy(app)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)

# User model must inherit from UserMixin
class User(UserMixin,db.Model):
    # Define your User model with fields for username, hashed password, etc.
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

@app.route("/")
@login_required
def index():
    # Index page
    pass

@app.route('/register', methods=['GET', 'POST'])
def register():
    # Handle user registration
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # Check if username is already taken
        user = User.query.filter_by(username=username).first()
        if user:
            return 'Username already exists. Please choose another username.'

        # Hash the password
        password_hash = generate_password_hash(password)

        # Create a new user instance
        new_user = User(username=username, password_hash=password_hash)

        # Add the new user to the database
        db.session.add(new_user)
        db.session.commit()

        return 'Registered successfully!'
        # redirect to login page
    return render_template('register.html')

# User loader callback for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/login', methods=['GET', 'POST'])
def login():
    # Handle user login
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # Query the database for the user
        user = User.query.filter_by(username=username).first()

        # Check if user exists and password is correct
        if user and check_password_hash(user.password_hash, password):
            # Log the user in
            login_user(user)
            return redirect(url_for('index'))
        else:
            return 'Invalid username or password'

    return render_template('login.html')

@app.route('/check_password', methods=['POST'])
def check_password():
    # check a password using your pwned_api_check function
    # store the checked password in the database
    pass

if __name__ == '__main__':
    app.run(debug=True)