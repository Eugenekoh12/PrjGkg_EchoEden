from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash
from flask_mysqldb import MySQL
from flask_bcrypt import Bcrypt
from forms import RegistrationForm
bcrypt = Bcrypt()
import MySQLdb.cursors
import re
app = Flask(__name__)
app.secret_key = 'the722semanticTOBOGGANS5smoothly.leutinizesTHEpointy3barrelOFgunpowder'
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'Ech03den'
app.config['MYSQL_PASSWORD'] = 'Pan4will.FLEXmy7adviser'
app.config['MYSQL_DB'] = 'echoeden'
app.config['MYSQL_PORT'] = 3306
mysql = MySQL(app)
user_db = {}

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        username = form.username.data
        email = form.email.data
        password = form.password.data

        if username in user_db:
            flash('Username already exists', 'danger')
            return redirect(url_for('register'))

        salt = bcrypt.gensalt()
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)

        # Save user details to the database (replace with DB operations)
        user_db[username] = {
            'email': email,
            'hashed_password': hashed_password
        }

        flash('Account created for {}! You can now log in.'.format(username), 'success')
        return redirect(url_for('login'))

    return render_template('register.html', title='Register', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Retrieve hashed password from the database (replace with DB retrieval)
        stored_user = user_db.get(username)
        if not stored_user:
            flash('Invalid username or password', 'danger')
            return redirect(url_for('login'))

        stored_hashed_password = stored_user['hashed_password']

        # Check if the provided password matches the stored hashed password
        if bcrypt.checkpw(password.encode('utf-8'), stored_hashed_password):
            flash('Login successful!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid username or password', 'danger')
            return redirect(url_for('login'))

    return render_template('login.html', title='Login')

# Manual Test Function
def test_password_hashing():
    password = "my_secretpassword"
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    print("Original Password:", password)
    print("Salt:", salt)
    print("Hashed Password:", hashed_password)
    print("Check Hashing:", bcrypt.checkpw(password.encode('utf-8'), hashed_password))

if __name__ == '__main__':
    test_password_hashing()  # Run the manual test
    app.run(debug=True)




