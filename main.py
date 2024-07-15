from flask import Flask, render_template, request, redirect, url_for, session, flash, abort
from flask_mysqldb import MySQL
from flask_bcrypt import Bcrypt
from forms import RegistrationForm
from flask_mail import Mail, Message
from datetime import datetime
import MySQLdb.cursors, re, json, requests, pyotp, time, qrcode, io, base64
from authlib.integrations.flask_client import OAuth

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
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = 'echoedenn@gmail.com'
app.config['MAIL_PASSWORD'] = 'edls docn byvz qcgd'
mail = Mail(app)

@app.context_processor
def inject_now():
    return {'now': datetime.utcnow()}

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

        if not account:
            flash('Invalid username or password', 'warning')
            send_login_notification(username, False, request.remote_addr, "Regular Login")
            return redirect(url_for('login'))

        stored_hashed_password = account['password_hash']

        if bcrypt.check_password_hash(stored_hashed_password, password):
            cursor.execute("SELECT * FROM account_settings WHERE user_id = %s", (account['id'],))
            settings = cursor.fetchone()
            cursor.close()

            if settings and settings['2fa_token_totp']:
                session['tmp_user'] = {'username': username, 'password_hash': stored_hashed_password}
                return redirect(url_for('verify_totp'))
            else:
                session['2fa'] = False
                session['username'] = username
                session['user'] = {'username': username, 'email': account['email']}
                flash('Login successful!', 'success')
                send_login_notification(account['email'], True, request.remote_addr, "Regular Login")
                return redirect(url_for('home'))
        else:
            flash('Invalid username or password', 'warning')
            send_login_notification(account['email'], False, request.remote_addr, "Regular Login")
            return redirect(url_for('login'))

    return render_template('login.html', title='Login')

# @app.route('/home')
# def home():
#     return "Welcome to the Home Page"

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

        # google people API - https://developers.google.com/people/api/rest/v1/people/get
        # Google OAuth 2.0 playground - https://developers.google.com/oauthplayground
        # make sure you enable the Google People API in the Google Developers console under "Enabled APIs & services" section
        personDataUrl = "https://people.googleapis.com/v1/people/me?personFields=genders,birthdays,emailAddresses"
        personData = requests.get(personDataUrl, headers={
            "Authorization": f"Bearer {token['access_token']}"
        }).json()
        token["personData"] = personData

        session["user"] = token
        hashed_token = bcrypt.generate_password_hash(json.dumps(token)).decode('utf-8')  # Hash the token
        session["oauth_token"] = hashed_token  # Store the hashed token in the session

        # Extract email from personData
        email = personData.get('emailAddresses', [{}])[0].get('value')
        session['email'] = email

        if email:
            send_login_notification(email, True, request.remote_addr, "Google Login")
        else:
            print("No email found in Google account data")

        flash('Google Login successful!', 'success')
        return redirect(url_for("home"))
    except Exception as e:
        print(f"Google login failed: {str(e)}")
        flash(f'Google login failed: {str(e)}', 'warning')
        return redirect(url_for("home"))


@app.route("/")
def home():
    return render_template("home.html", session=session.get("user"),
                           pretty=json.dumps(session.get("user"), indent=4))

@app.route("/google-login")
def googleLogin():
    if "user" in session:
        abort(404)
        # Need to inform user they're logged in.
    return oauth.myApp.authorize_redirect(redirect_uri=url_for("googleCallback", _external=True))

@app.route("/logout")
def logout():
    session['2fa'] = None
    session['username'] = None
    session.pop("user", None)
    return redirect(url_for("home"))

# if __name__ == "__main__":
#     app.run(host="0.0.0.0", port=appConf.get(
#         "FLASK_PORT"), debug=True)

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

@app.route('/oauth_username', methods=['GET', 'POST'])
def oauth_username():
    form = RegistrationForm()
    if form.validate_on_submit():
        username = form.username.data
        email = session['email']
        password = bcrypt.generate_password_hash('random_password').decode('utf-8')  # Generate a random password
        hashed_token = session['oauth_token']  # Retrieve the hashed token from the session

        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute("SELECT * FROM accounts WHERE username = %s", (username,))
        account = cursor.fetchone()

        if account:
            flash('Username already exists', 'warning')
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
            "INSERT INTO account_settings (user_id, oauth_token) VALUES (%s, %s)",
            (user_id, hashed_token)  # Store the hashed token in the account_settings table
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

if __name__ == "__main__":
    app.run(debug=True)