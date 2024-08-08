from flask import Flask, render_template, request, redirect, url_for, session, flash, abort
from flask_mysqldb import MySQL
from flask_bcrypt import Bcrypt
from forms import RegistrationForm
from flask_mail import Mail, Message
from datetime import datetime, timedelta
import MySQLdb.cursors, re, json, requests, pyotp, time, qrcode, io, base64
from authlib.integrations.flask_client import OAuth
import secrets
from functools import wraps
import uuid
from flask_wtf import FlaskForm, RecaptchaField
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo

#captcha Glenys


class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    recaptcha = RecaptchaField()
    submit = SubmitField('Sign Up')


app = Flask(__name__)
bcrypt = Bcrypt(app)
mail = Mail(app)

app.secret_key = 'the722semanticTOBOGGANS5smoothly.leutinizesTHEpointy3barrelOFgunpowder'
# app.permanent_session_lifetime = timedelta(minutes=60)
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'Ech03den'
app.config['MYSQL_PASSWORD'] = 'Pan4will.FLEXmy7adviser'
app.config['MYSQL_DB'] = 'echoeden'
app.config['MYSQL_PORT'] = 3306
app.config['RECAPTCHA_PUBLIC_KEY'] = '6Lc4FiIqAAAAAI-SrMHabpsRbXQ4LnpcBQgWMAnF'
app.config['RECAPTCHA_PRIVATE_KEY'] = '6Lc4FiIqAAAAAJHWbk-y1XV0bu59SCf60wcz64RD'
mysql = MySQL(app)

# Flask-Mail configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = 'echoedenn@gmail.com'
app.config['MAIL_PASSWORD'] = 'edls docn byvz qcgd'
mail = Mail(app)

@app.context_processor
def inject_now():
    return {'now': datetime.utcnow()}


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'session_id' not in session:
            return redirect(url_for('login'))

        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute("SELECT * FROM user_sessions WHERE session_id = %s", (session['session_id'],))
        user_session = cursor.fetchone()

        if not user_session:
            return redirect(url_for('login'))

        # Update last activity
        cursor.execute("UPDATE user_sessions SET last_activity = CURRENT_TIMESTAMP WHERE session_id = %s",
                       (session['session_id'],))
        mysql.connection.commit()

        return f(*args, **kwargs)

    return decorated_function

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
            flash('Username already exists', 'warning')
            return redirect(url_for('register'))

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        # Insert a new record into the settings table and get the settings_id
        cursor.execute("INSERT INTO settings (theme) VALUES (0)")
        mysql.connection.commit()
        settings_id = cursor.lastrowid

        # Insert new user into the accounts table and get the user_id
        cursor.execute(
            "INSERT INTO accounts (username, email, password_hash, settings_id) VALUES (%s, %s, %s, %s)",
            (username, email, hashed_password, settings_id)
        )
        mysql.connection.commit()
        user_id = cursor.lastrowid

        # Insert a new record into the account_settings table for the new user
        cursor.execute(
            "INSERT INTO account_settings (user_id) VALUES (%s)",
            (user_id,)
        )
        cursor.execute(
            "INSERT INTO associates (user_id) VALUES (%s)",
            (user_id,)
        )
        mysql.connection.commit()
        cursor.close()

        flash('Account created for {}! You can now log in.'.format(username), 'success')
        return redirect(url_for('home'))

    return render_template('register.html', title='Register', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute("SELECT * FROM accounts WHERE username = %s", (username,))
        account = cursor.fetchone()

        if account and bcrypt.check_password_hash(account['password_hash'], password):
            # Check for existing active sessions
            cursor.execute("SELECT * FROM user_sessions WHERE user_id = %s AND last_activity > %s",
                           (account['id'], datetime.now() - timedelta(minutes=30)))
            existing_session = cursor.fetchone()

            if existing_session:
                # Invalidate previous session
                cursor.execute("UPDATE user_sessions SET status = 'logged_out' WHERE user_id = %s", (account['id'],))
                mysql.connection.commit()
                flash('Previous session has been logged out.', 'info')

            # Generate a unique session ID
            session_id = str(uuid.uuid4())

            # Store session details in the database
            session_data = {
                'user_id': account['id'],
                'username': account['username'],
                'login_time': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            cursor.execute("""
                INSERT INTO user_sessions (session_id, user_id, ip_address, user_agent, data, status)
                VALUES (%s, %s, %s, %s, %s, 'active')
            """, (session_id, account['id'], request.remote_addr, request.user_agent.string, json.dumps(session_data)))
            mysql.connection.commit()

            # Store session ID in Flask session
            session['session_id'] = session_id
            session['user_id'] = account['id']
            session['username'] = account['username']

            flash('Login successful!', 'success')
            return redirect(url_for('home'))  # This line ensures redirection to home page
        else:
            flash('Invalid username or password', 'warning')

    return render_template('login.html', title='Login')


def send_login_notification(email, success, ip_address, login_type):
    status = "successful" if success else "failed"
    msg = Message(f'Login Attempt Notification - {status.capitalize()}',
                  sender=app.config['MAIL_USERNAME'],
                  recipients=[email])
    msg.body = f"""Dear User,

A {status} login attempt was made on your Echo Eden account using {login_type}.

Details:
- Time: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
- IP Address: {ip_address}

If this was you, you can ignore this message. If not, please take appropriate action to secure your account.

Best regards,
Echo Eden
"""
    try:
        print(f"Attempting to send email to {email}")
        mail.send(msg)
        print(f"Email sent successfully to {email}")
    except Exception as e:
        print(f"Failed to send email notification to {email}: {str(e)}")
        app.logger.error(f"Failed to send email notification to {email}: {str(e)}")
#session
@app.route('/session-history')
@login_required
def session_history():
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("""
        SELECT session_id, ip_address, user_agent, last_activity, status,
               CASE WHEN status = 'logged_out' THEN last_activity ELSE NULL END AS logout_time
        FROM user_sessions 
        WHERE user_id = %s 
        ORDER BY last_activity DESC
    """, (session['user_id'],))
    sessions = cursor.fetchall()
    cursor.close()

    # Process the sessions to extract browser information
    for session_data in sessions:
        user_agent = session_data['user_agent'].lower()
        if 'chrome' in user_agent:
            session_data['browser'] = 'Chrome'
        elif 'firefox' in user_agent:
            session_data['browser'] = 'Firefox'
        elif 'safari' in user_agent:
            session_data['browser'] = 'Safari'
        elif 'edge' in user_agent:
            session_data['browser'] = 'Edge'
        elif 'opera' in user_agent:
            session_data['browser'] = 'Opera'
        else:
            session_data['browser'] = 'Other'

    return render_template('session_history.html', sessions=sessions)




# https://www.youtube.com/watch?v=fZLWO3_V06Q - reference video
appConf = {
    "OAUTH2_CLIENT_ID": "955694757224-toh23qh3o8ci3gp4q85euak51jqbv5fm.apps.googleusercontent.com",
    "OAUTH2_CLIENT_SECRET": "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",
    "OAUTH2_META_URL": "https://accounts.google.com/.well-known/openid-configuration",
    "FLASK_SECRET": "the722semanticTOBOGGANS5smoothly.leutinizesTHEpointy3barrelOFgunpowder",
    "FLASK_PORT": 5000
}

app.secret_key = appConf.get("FLASK_SECRET")

oauth = OAuth(app)
# list of google scopes - https://developers.google.com/identity/protocols/oauth2/scopes
oauth.register(
    "myApp",
    client_id=appConf.get("OAUTH2_CLIENT_ID"),
    client_secret=appConf.get("OAUTH2_CLIENT_SECRET"),
    client_kwargs={
        "scope": "openid profile email https://www.googleapis.com/auth/user.birthday.read https://www.googleapis.com/auth/user.gender.read",
        # 'code_challenge_method': 'S256'  # enable PKCE
    },
    server_metadata_url=f'{appConf.get("OAUTH2_META_URL")}',
)


@app.route("/signin-google")
def googleCallback():
    try:
        token = oauth.myApp.authorize_access_token()

        personDataUrl = "https://people.googleapis.com/v1/people/me?personFields=genders,birthdays,emailAddresses"
        personData = requests.get(personDataUrl, headers={
            "Authorization": f"Bearer {token['access_token']}"
        }).json()
        token["personData"] = personData

        # Extract email from personData
        email = personData.get('emailAddresses', [{}])[0].get('value')
        session['email'] = email

        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute("SELECT * FROM accounts WHERE email = %s", (email,))
        account = cursor.fetchone()

        if account:
            # If an account with the email already exists, log in with the existing account
            session['username'] = account['username']
            user_id = account['id']
        else:
            # Create a new account
            username = f"user_{uuid.uuid4().hex[:8]}"  # Generate a temporary username
            hashed_password = bcrypt.generate_password_hash('temporary_password').decode('utf-8')

            cursor.execute("INSERT INTO settings (theme) VALUES (0)")
            mysql.connection.commit()
            settings_id = cursor.lastrowid

            cursor.execute(
                "INSERT INTO accounts (username, email, password_hash, settings_id) VALUES (%s, %s, %s, %s)",
                (username, email, hashed_password, settings_id)
            )
            mysql.connection.commit()
            user_id = cursor.lastrowid

            cursor.execute(
                "INSERT INTO account_settings (user_id) VALUES (%s)",
                (user_id,)
            )
            cursor.execute(
                "INSERT INTO associates (user_id) VALUES (%s)",
                (user_id,)
            )
            mysql.connection.commit()

            session['username'] = username

        # Generate a unique session ID
        session_id = str(uuid.uuid4())

        # Store session details in the database
        session_data = {
            'user_id': user_id,
            'username': session['username'],
            'login_time': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        cursor.execute("""
            INSERT INTO user_sessions (session_id, user_id, ip_address, user_agent, data, status)
            VALUES (%s, %s, %s, %s, %s, 'active')
        """, (session_id, user_id, request.remote_addr, request.user_agent.string, json.dumps(session_data)))
        mysql.connection.commit()

        # Store session ID in Flask session
        session['session_id'] = session_id
        session['user_id'] = user_id

        if email:
            send_login_notification(email, True, request.remote_addr, "Google Login")
        else:
            print("No email found in Google account data")

        flash('Google Login successful! Please create a username:', 'success')
        return redirect(url_for('oauth_username'))
    except Exception as e:
        print(f"Google login failed: {str(e)}")
        flash(f'Google login failed: {str(e)}', 'warning')
        return redirect(url_for("home"))


@app.route("/")
@app.route("/home")
def home():
    return render_template("home.html", user=session.get('username'))

@app.route("/google-login")
def googleLogin():
    if "user" in session:
        flash('User already logged in!', 'warning')
        return redirect(url_for("home"))
    # if you are cayden comment the if statement cuz SOMEHOW IT DOESN'T WORK FOR HIM
        # Need to inform user they're logged in.
    return oauth.myApp.authorize_redirect(redirect_uri=url_for("googleCallback", _external=True))


@app.route("/logout")
def logout():
    session['2fa'] = None
    session['username'] = None
    session['user'] = None
    session.pop("2fa", None)
    session.pop("username", None)
    session.pop("user", None)
    if 'session_id' in session:
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute("""
            UPDATE user_sessions 
            SET status = 'logged_out'
            WHERE session_id = %s
        """, (session['session_id'],))
        mysql.connection.commit()
        cursor.close()

    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for("home"))

@app.route('/setup-totp', methods=['GET', 'POST'])
def setup_totp():
    if 'user' not in session:
        return redirect(url_for('login'))

    username = session['user']['username']

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT * FROM accounts WHERE username = %s", (username,))
    account = cursor.fetchone()

    cursor.execute("SELECT * FROM account_settings WHERE user_id = %s", (account['id'],))
    settings = cursor.fetchone()

    if request.method == 'POST':
        token = request.form['token']
        if pyotp.TOTP(settings['2fa_token_totp']).verify(token):
            session['2fa'] = True
            flash('2FA setup successful!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid token', 'warning')

    if settings and settings['2fa_token_totp']:
        secret = settings['2fa_token_totp']
    else:
        secret = pyotp.random_base32()
        cursor.execute("UPDATE account_settings SET 2fa_token_totp = %s WHERE user_id = %s", (secret, account['id'],))
        mysql.connection.commit()

    uri = pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name='EchoEden')
    img = qrcode.make(uri)
    stream = io.BytesIO()
    img.save(stream, 'PNG')
    stream.seek(0)
    img_b64 = base64.b64encode(stream.read()).decode()

    cursor.close()

    return render_template('setup_totp.html', img_b64=img_b64, secret=secret)

@app.route('/verify-totp', methods=['GET', 'POST'])
def verify_totp():
    if 'tmp_user' not in session:
        return redirect(url_for('login'))

    username = session['tmp_user']['username']

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT * FROM accounts WHERE username = %s", (username,))
    account = cursor.fetchone()

    cursor.execute("SELECT * FROM account_settings WHERE user_id = %s", (account['id'],))
    settings = cursor.fetchone()
    cursor.close()

    if request.method == 'POST':
        token = request.form['token']
        if pyotp.TOTP(settings['2fa_token_totp']).verify(token):
            session['2fa'] = True
            session['username'] = username
            session['user'] = session['tmp_user']
            del session['tmp_user']
            flash('Login successful!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid token', 'warning')

    return render_template('verify_totp.html')

@app.route('/oauth-username', methods=['GET', 'POST'])
def oauth_username():
    form = RegistrationForm()
    password_base = secrets.token_urlsafe(64)
    password = bcrypt.hashpw(password_base.encode(), bcrypt.gensalt(rounds=12))
    if form.validate_on_submit():
        username = form.username.data
        email = session['email']
        password = bcrypt.generate_password_hash('random_password').decode('utf-8')  # Generate a random password
        hashed_token = session['oauth_token']  # Retrieve the hashed token from the session

        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute("SELECT * FROM accounts WHERE username = %s", (username,))
        account = cursor.fetchone()

        if account:
            flash('Username already exists! Please try again.', 'warning')
            return redirect(url_for('oauth_username'))

        # Insert a new record into the settings table and get the settings_id
        cursor.execute("INSERT INTO settings (theme) VALUES (0)")
        mysql.connection.commit()
        settings_id = cursor.lastrowid
        session['username'] = username

        # Insert new user into the accounts table and get the user_id
        cursor.execute(
            "INSERT INTO accounts (username, email, password_hash, settings_id) VALUES (%s, %s, %s, %s)",
            (username, email, password, settings_id)
        )
        mysql.connection.commit()
        user_id = cursor.lastrowid

        # Insert a new record into the account_settings table for the new user
        cursor.execute(
            "INSERT INTO account_settings (user_id, oauth_token, generated_password) VALUES (%s, %s, %s)",
            (user_id, hashed_token, 1)  # Store the hashed token and set generated_password to 1
        )
        cursor.execute(
            "INSERT INTO associates (user_id) VALUES (%s)",
            (user_id,)
        )
        mysql.connection.commit()
        cursor.close()

        flash('Account created for {}! You can now log in.'.format(username), 'success')
        return redirect(url_for('home'))

    return render_template('oauth_username.html', title='Choose Username', form=form)


for rule in app.url_map.iter_rules():
    print(rule)

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)