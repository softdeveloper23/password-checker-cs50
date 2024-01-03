import os
import datetime

from cs50 import SQL
from flask import Flask, render_template, request, redirect, url_for, session
from flask_session import Session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
# Import other necessary modules and functions

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////tmp/test.db'  # Or other database URI
db = SQLAlchemy(app)

class User(db.Model):
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

@app.route('/login', methods=['GET', 'POST'])
def login():
    # handle user login
    pass

@app.route('/check_password', methods=['POST'])
def check_password():
    # check a password using your pwned_api_check function
    # store the checked password in the database
    pass

if __name__ == '__main__':
    app.run(debug=True)