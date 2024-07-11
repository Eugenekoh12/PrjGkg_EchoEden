from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_mysqldb import MySQL
from flask_bcrypt import Bcrypt
from forms import RegistrationForm
from flask_mail import Mail, Message
import MySQLdb.cursors
import re

app = Flask(__name__)
bcrypt = Bcrypt(app)
mail = Mail(app)

app.secret_key = 'the722semanticTOBOGGANS5smoothly.leutinizesTHEpointy3barrelOFgunpowder'
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'Ech03den'
app.config['MYSQL_PASSWORD'] = 'Pan4will.FLEXmy7adviser'
app.config['MYSQL_DB'] = 'echoeden'
app.config['MYSQL_PORT'] = 3306
mysql = MySQL(app)

# Flask-Mail configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] = 'echoedenn@gmail.com'
app.config['MAIL_PASSWORD'] = 'echoeden123'
mail = Mail(app)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        username = form.username.data
        email = form.email.data
        password = form.password.data

        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute("SELECT * FROM accounts WHERE username = %s", (username,))
        account = cursor.fetchone()

        if account:
            flash('Username already exists', 'danger')
            return redirect(url_for('register'))

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        # Insert a new record into the settings table and get the settings_id
        cursor.execute("INSERT INTO settings (theme) VALUES (0)")
        mysql.connection.commit()
        settings_id = cursor.lastrowid

        # Insert new user into the accounts table
        cursor.execute(
            "INSERT INTO accounts (username, email, password_hash, settings_id) VALUES (%s, %s, %s, %s)",
            (username, email, hashed_password, settings_id)
        )
        mysql.connection.commit()
        cursor.close()

        flash('Account created for {}! You can now log in.'.format(username), 'success')
        return redirect(url_for('login'))

    return render_template('register.html', title='Register', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute("SELECT * FROM accounts WHERE username = %s", (username,))
        account = cursor.fetchone()
        cursor.close()

        if not account:
            flash('Invalid username or password', 'danger')
            return redirect(url_for('login'))

        stored_hashed_password = account['password_hash']

        if bcrypt.check_password_hash(stored_hashed_password, password):
            flash('Login successful!', 'success')
            # Send email notification
            send_login_notification(account['email'], username)
            return redirect(url_for('home'))
        else:
            flash('Invalid username or password', 'danger')
            return redirect(url_for('login'))

    return render_template('login.html', title='Login')

@app.route('/home')
def home():
    return "Welcome to the Home Page"

def send_login_notification(email, username):
    msg = Message('Login Attempt Notification',
                  sender='your-email@gmail.com',
                  recipients=[email])
    msg.body = f"Hello {username},\n\nSomeone has attempted to log into your account on ExampleApp. If this was you, you can ignore this message. If not, please take appropriate action."
    mail.send(msg)


if __name__ == '__main__':
    app.run(debug=True)







