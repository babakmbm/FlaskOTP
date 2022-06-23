import base64
import random
from io import BytesIO
from flask import *
import sqlite3
from sqlite3 import *
from twilio.rest import *
from flask_bootstrap import Bootstrap
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from pyqrcode import *

import pyotp
from flask_mail import Mail, Message

app = Flask(__name__)
app.config["SECRET_KEY"] = "MY_SECRET_KEY_OTP_FLASK"
Bootstrap(app)
app.config['DEBUG'] = True
app.config['TEST'] = False
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
#app.config['MAIL_DEBUG'] = True
app.config['MAIL_USERNAME'] = '-'
app.config['MAIL_PASSWORD'] = '-'
app.config['MAIL_DEFAULT_SENDER'] = '-'
app.config['MAIL_MAX_EMAILS'] = None
#app.config['MAIL_SUPRESS_SEND'] = False
app.config['MAIL_ASCII_ATTACHMENTS'] = False

mail = Mail(app)
'''mail = Mail()
mail.init_app(app)'''

def emailQR(email):
    filename = 'qrcode.png'
    with app.open_resource(filename) as fp:
        msg = Message('Please Keep This Safe!', recipients=[email])
        msg.html = f"<h1>This is your QR Code!</h1><br>" \
                   f"<h5 >Instructions</h5>" \
                   f"<ul>" \
                   f"<li>Download Free OTP Authenticator on your mobile</li>" \
                   f"<a href='https://play.google.com/store/apps/details?id=org.fedorahosted.freeotp&hl=en_GB&gl=US' target='_blank'>Google Play Store</a>" \
                   "<a href='https://apps.apple.com/us/app/freeotp-authenticator/id872559395' target='_blank'>Apple App Store</a>" \
                   "<li>Scan The QR code sent to you using the app</li>" \
                   "<li>Enter the one time key into the box</li>" \
                   "<li>Submit the generated key to login</li>" \
                   "</ul>"
        msg.attach(filename, 'image/', fp.read())
        mail.send(msg)
    os.remove(filename)

    return 'Email Sent!'


@app.before_request
def before_request():
    if 'email' in session:
        con = create_connection()
        c = con.cursor()
        c.execute(f"SELECT * FROM user WHERE user.email = '{session['email']}'")
        user_data = c.fetchall()
        con.close()
        g.user = user_data[0]
    else:
        g.user = None


def create_connection():
    conn = None
    try:
        conn = sqlite3.connect('identifier.sqlite')
        #print("connection has been made to the DB!")
    except Error as e:
        print(e)
    return conn


@app.route('/')
def index():
    if 'phone' in session or 'email' in session:
        logout()
        #flash("Logged out for test!", "secondary")
        #return redirect(url_for('index'))
    return render_template('index.html')


@app.route("/login/")
def login():
    return render_template("login.html")


# login form route
@app.route("/login/", methods=["POST"])
def login_form():
    email = request.form.get("username")
    password = request.form.get("password")
    con = create_connection()
    c = con.cursor()
    c.execute(f"SELECT * FROM user WHERE user.email = '{email}'")
    user_data = c.fetchall()
    con.close()
    if user_data:
        print(user_data[0][4])
        print("Email was found!")
        if check_password_hash(user_data[0][5], password):
            print("Password Match!")
            session['phone'] = str(user_data[0][3])
            session['email'] = str(user_data[0][4])
            return redirect(url_for('smsORqr'))
        else:
            print("Password is wrong!")
            flash("The Password did not match the email address", "danger")
            return redirect(url_for("otpOption"))
    else:
        flash("This email is not registered", "danger")
        return redirect(url_for("login"))
    return render_template('login.html')


@app.route('/smsORqr/')
def smsORqr():
    if 'email' and 'phone' in session:
        print('Correcto!')
        return render_template('smsORqr.html')
    else:
        flash("You cannot access this page without first logging in with your password!", 'danger')
        return redirect(url_for('login'))


@app.route('/smsORqr/', methods=['POST'])
def smsORqr_form():
    choice = request.form.get('options')
    if choice == 'sms':
        print('Chose SMS OTP!')
        flash("You chose to authenticate with SMS", "secondary")
        return redirect(url_for('enterPhoneOTP'))
    else:
        flash("You chose to authenticate with QR Code", "secondary")
        return redirect(url_for('enterotpqr'))
        print('Chose QR COde!')


@app.route('/enterotpqr', methods=['GET'])
def enterotpqr():
    if 'email' and 'phone' in session:
        print('Correcto!')
        return render_template('enterOTPqr.html')
    else:
        flash("You cannot access this page without first logging in with your password!", 'danger')
        return redirect(url_for('login'))

@app.route('/enterotpqr', methods=['POST'])
def enterotpqr_form():
    token = request.form['token']
    email = session['email']
    phone = session['phone']
    con = create_connection()
    c = con.cursor()
    c.execute(f"SELECT * FROM user WHERE user.email = '{email}' OR user.phoneNumber = '{phone}'")
    user_data = c.fetchall()
    print(user_data)
    if user_data is None:
        flash("Two factor authentication Failed!", "danger")
        return redirect(url_for('login'))
    else:
        otp_secret = str(user_data[0][7])
        qrFlag = verify_totp(otp_secret, token)
        print('token: ', token)
        print("secret: ", otp_secret)
        print("Verification: ", qrFlag)
        if qrFlag is True:
            flash("Two factor authentication Successful!", "success")
            return redirect(url_for('dashboard'))
        else:
            flash('The Two factor Authentication failed!', 'danger')
            logout()
            return redirect(url_for('dashboard'))

@app.route('/qrcode')
def qrcode():
    if 'email' not in session or 'phone' not in session:
        flash("Registration went wrong please try again", "danger")
        return redirect(url_for('register'))
    else:
        email = session['email']
        phone = session['phone']
        con = create_connection()
        c = con.cursor()
        c.execute(f"SELECT * FROM user WHERE user.email = '{email}' OR user.phoneNumber = '{phone}'")
        user_data = c.fetchall()
        con.close()
    if user_data is None:
        flash("Two factor setup went wrong!", "danger")
        return redirect(url_for('register'))
    else:
        otp_secret = str(user_data[0][7])
        print('Secret used to generate QR Code:', otp_secret)
        # for added security, remove email and phone from session

        '''del session['phone']
        del session['email']'''

        # render qrcode for FreeTOTP
        url = pyqrcode.create(get_totp_uri(email, otp_secret))
        stream = BytesIO()
        url.svg(stream, scale=5)
        url.png('qrcode.png', scale=8)
        emailQR(email)
        return stream.getvalue(), 200, {
            'Content-Type': 'image/svg+xml',
            'Cache-Control': 'no-cache, no-store, must-revalidate',
            'Pragma': 'no-cache',
            'Expires': '0'}

@app.route('/enterPhoneOTP')
def enterPhoneOTP():
    if 'email' and 'phone' in session:
        return render_template('enterPhoneOTP.html')
    else:
        flash("You cannot access this page without first logging in with your password!", 'danger')
        return redirect(url_for('login'))

@app.route('/getOTPsms', methods=['GET'])
def getOTPsms():
    if 'email' and 'phone' in session:
        return render_template('getOTPsms.html')
    else:
        flash("You cannot access this page without first logging in with your password!", 'danger')
        return redirect(url_for('login'))


@app.route('/getOTPsms', methods=['POST'])
def getOTPsms_form():
    phone = request.form['phone']
    # TODO: Check if the number is in the database
    otpFlag = getOTPApi(phone)
    if otpFlag:
        flash("Enter the number that was just sent to your phone", "primary")
        return render_template('enterOTPsms.html')
    else:
        flash("This email is not registered", "danger")
        return redirect(url_for("enterPhoneOTP"))

@app.route('/validateOTP', methods=['POST'])
def validateOTP():
    otp = request.form['otp']
    if 'response' in session:
        s = session['response']
        session.pop('response', None)
        if s == otp:
            flash("Two factor authentication Successful!", "success")
            return render_template('dashboard.html', message="Two factor authentication Successful!")
        else:
            flash('The Two factor Authentication failed!', 'danger')
            logout()
            return render_template('dashboard.html', message="The Two factor Authentication failed!")

def generateOTP():
    return random.randrange(100000, 999999)

def getOTPApi(phoneNumber):
    account_sid = 'AC563feb6b230d4ff71e48d4ce4ce627fb'
    auth_token = '629e166d8866227e9bb6e4dbdf5f233e'
    otp = generateOTP()
    client = Client(account_sid, auth_token)
    session['response'] = str(otp)
    message = client.messages.create(
        messaging_service_sid='MG1c5695a4134b9896ec7d219d3b656bbc',
        body=f"Your One Time Password for GHAZAL FLASK-OTP: {otp}",
        to=phoneNumber
    )
    if message.sid:
        return True
    else:
        return False


@app.route('/register/')
def register():
    # if user is logged in go back to index
    logout()
    return render_template('register.html')


@app.route('/register/', methods=['POST'])
def register_form():
    firstname = request.form['firstname']
    lastname = request.form['lastname']
    phone = request.form['phone']
    email = request.form['email']
    password = request.form['password']
    hashedpassword = generate_password_hash(password, method='sha512')
    timecreated = int(datetime.utcnow().timestamp())
    otp_secret = base64.b32encode(os.urandom(10)).decode('utf-8')
    print(firstname)
    print(lastname)
    print(phone)
    print(email)
    print(hashedpassword)
    print(timecreated)

    con = create_connection()
    c = con.cursor()
    c.execute(f"SELECT * FROM user WHERE user.email = '{email}' OR user.phoneNumber = '{phone}'")
    user_data = c.fetchall()
    if user_data:
        print("Email or phone number already exists!")
        con.commit()
        con.close()
        flash("Email or phone number already exists! Please choose another one", "danger")
        return redirect(url_for("register"))
    else:
        c.execute(
            f"INSERT INTO user(firstName, lastName, phoneNumber, email, hashedPassword, timeCreated, otp_secret) VALUES('{firstname}','{lastname}','{phone}','{email}','{hashedpassword}', {timecreated}, '{otp_secret}')")
        con.commit()
        con.close()
        session['email'] = str(email)
        session['phone'] = str(phone)
        return redirect(url_for('QR_two_factor_setup'))

    return render_template('register.html')

# This happens after the registration
@app.route('/QR_two_factor_setup')
def QR_two_factor_setup():
    if 'email' not in session or 'phone' not in session:
        flash("Registration went wrong please try again", "danger")
        return redirect(url_for('register'))
    else:
        email = session['email']
        phone = session['phone']
        con = create_connection()
        c = con.cursor()
        c.execute(f"SELECT * FROM user WHERE user.email = '{email}' OR user.phoneNumber = '{phone}'")
        user_data = c.fetchall()
    if user_data is None:
        flash("Two factor setup went wrong!", "danger")
        return redirect(url_for('register'))
    else:
        '''flash("We are fine", "success")
        return redirect(url_for('register'))'''
        # since this page contains the sensitive qrcode, make sure the browser
        # does not cache it
        return render_template('QRtwoFactorSetup.html'), 200, {
            'Cache-Control': 'no-cache, no-store, must-revalidate',
            'Pragma': 'no-cache',
            'Expires': '0'}


def set_otp_secret(email, phone):
    if email is not None and phone is not None:
        otp_secret = base64.b32encode(os.urandom(10)).decode('utf-8')
        con = create_connection()
        c = con.cursor()
        c.execute(f"UPDATE user SET otp_secret = '{otp_secret}' WHERE user.email = '{email}' OR user.phoneNumber = '{phone}'")
        con.commit()
        con.close()
        return otp_secret
    else:
        flash('Something went wrong when creating otp_secret', 'danger')
        return redirect(url_for('register'))

def get_totp_uri(email, otp_secret):
    return 'otpauth://totp/2FA-Ghazal:{0}?secret={1}&issuer=2FA-Ghazal'.format(email, otp_secret)

def verify_totp(otp_secret, token):
    totp = pyotp.TOTP(otp_secret)
    return totp.verify(token)

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'email' and 'phone' in session:
        print('Correcto!')
        return render_template('dashboard.html')
    else:
        flash("You cannot access this page without first logging in with your password!", 'danger')
        return redirect(url_for('login'))


@app.route('/logout')
def logout():
    if 'phone' in session or 'email' in session:
        session.pop('phone', None)
        session.pop('email', None)
        flash("Logged out for testing!", "secondary")
        return redirect(url_for('index'))
    else:
        flash("Not Logged in!", "secondary")
        return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
