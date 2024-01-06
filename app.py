import os
import datetime
import requests
import hashlib


from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_session import Session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from helpers import apology
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField
from wtforms.validators import DataRequired, Length, EqualTo

# Import other necessary modules and functions

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///password_checker.db'
db = SQLAlchemy(app)

# Ensure templates are auto-reloaded
@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)

# User model must inherit from UserMixin
class User(UserMixin,db.Model):
    # Define your User model with fields for username, hashed password, etc.
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

# Create a model for storing the checked passwords
class CheckedPassword(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    password_hash = db.Column(db.String(128), nullable=False)
    times_seen = db.Column(db.Integer, nullable=False)
    date_checked = db.Column(db.DateTime, nullable=False)
    time_checked = db.Column(db.Time, nullable=False)
    result = db.Column(db.Boolean, nullable=False)


# Create a form class for the login form
class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=25)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    confirmation = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password', message="Passwords don't match")])

with app.app_context():
    db.create_all()

@app.route("/")
def index():
    if current_user.is_authenticated:
        return render_template('index.html')
    else:
        return render_template('welcome.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        # Check if username is already taken
        user = User.query.filter_by(username=username).first()
        if user:
            return apology('Username already exists. Please choose another username.', 400)
        # Hash the password
        password_hash = generate_password_hash(password)
        # Create a new user instance
        new_user = User(username=username, password_hash=password_hash)
        # Add the new user to the database
        db.session.add(new_user)
        db.session.commit()
        # Flash a success message
        flash('Your account has been created successfully, please login.')
        # redirect to login page
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

# User loader callback for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/login', methods=['GET', 'POST'])
def login():
    # Handle user login
    if request.method == 'POST':

        # Ensure username was submitted
        if not request.form['username']:
            return apology("must provide username", 400)

        # Ensure password was submitted
        elif not request.form['password']:
            return apology("must provide password", 400)

        # Get the username and password from the form
        username = request.form.get('username')
        password = request.form.get('password')

        # Query the database for the user
        user = User.query.filter_by(username=username).first()

        # Check if user exists and password is correct
        if user and check_password_hash(user.password_hash, password):
            # Log the user in
            login_user(user)

            # Flash a success message
            flash('You have been logged in successfully.')

            return redirect(url_for('index'))
        else:
            return apology('Invalid username or password', 400)

    return render_template('login.html')

@app.route('/check_password', methods=['POST'])
def check_password():
    if request.method == 'POST':
        password = request.form.get('password')
        hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        prefix, suffix = hash[:5], hash[5:]
        response = requests.get(f'https://api.pwnedpasswords.com/range/{prefix}')
        hashes = (line.split(':') for line in response.text.splitlines())
        count = next((int(count) for t, count in hashes if t == suffix), 0)
        checked_password = CheckedPassword.query.filter_by(password_hash=hash).first()
        if checked_password:
            checked_password.times_seen += 1
        else:
            checked_password = CheckedPassword(password_hash=hash, times_seen=1, date_checked=datetime.date.today(),
            time_checked=datetime.datetime.now().time(), result=bool(count))
            db.session.add(checked_password)
        db.session.commit()

        # Check if the password has been found
        if count:
            flash(f'The password has been found! This password has been seen {count} times before', 200)
        else:
            flash(f'The password has not been found!', 200)

    return render_template('index.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    # Flash a success message
    flash('You have been logged out successfully.')
    return redirect(url_for('index'))  # Or redirect to any other page

# Error handlers
@app.errorhandler(404)
def not_found_error(error):
    return apology('Page not found', 404)

@app.errorhandler(500)
def internal_error(error):
    # Rollback the session in case a database error occurred
    db.session.rollback()
    return apology('An internal error occurred', 500)

# Create a route for the history page
@app.route('/history')
@login_required
def history():
    password_history = CheckedPassword.query.all()
    return render_template('history.html', password_history=password_history)




if __name__ == '__main__':
    app.run(debug=True)