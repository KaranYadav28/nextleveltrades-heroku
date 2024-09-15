from flask import Flask, render_template, redirect, url_for, flash, request, session
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from wtforms import StringField, PasswordField, SubmitField, SelectField, FloatField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
from datetime import datetime, timedelta
from itsdangerous import URLSafeTimedSerializer
import pyotp
import logging
from authlib.integrations.flask_client import OAuth
from authlib.common.security import generate_token
from apscheduler.schedulers.background import BackgroundScheduler
import pytz
import hashlib
import requests
import asyncio
from bot import TradingBot
import ccxt
import threading



# Initialize the Flask application
app = Flask(__name__)
app.config['SECRET_KEY'] = 'KaranYadav'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'

# Flask-Mail configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'nextlevelstrades@gmail.com'  # Replace with your email
app.config['MAIL_PASSWORD'] = 'iasm waqt qlut jjek'  # Replace with your app-specific password
app.config['MAIL_DEFAULT_SENDER'] = 'nextlevelstrades@gmail.com'  # Replace with your email
active_bots = {}
# Initialize extensions
mail = Mail(app)
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
# OAuth configuration
bot_status={}
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id='606914266477-kogstbs60m7cnvplpa48hvr88tttm2m9.apps.googleusercontent.com',
    client_secret='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',
    access_token_url='https://accounts.google.com/o/oauth2/token',
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    userinfo_endpoint='https://www.googleapis.com/oauth2/v3/userinfo',
    jwks_uri='https://www.googleapis.com/oauth2/v3/certs',
    client_kwargs={'scope': 'openid profile email'},
)
app.config['TEMPLATES_AUTO_RELOAD'] = True

# PayU configuration
PAYU_KEY = "BfHohf"
PAYU_SALT = "YdxXtt8DiMRExSSRTE5itKa1Auu3FpfR"
PAYU_URL = "https://test.payu.in/_payment"  # Use https://secure.payu.in/_payment for live

# Set up logging for debugging
logging.basicConfig(level=logging.DEBUG)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    otp_secret = db.Column(db.String(16), nullable=False, default=pyotp.random_base32())
    subscription_plan = db.Column(db.String(20), nullable=True)
    subscription_start = db.Column(db.DateTime, nullable=True)
    subscription_end = db.Column(db.DateTime, nullable=True)
    subscription_active = db.Column(db.Boolean, default=False)

    # Method to verify the password hash
    def check_password(self, password):
        return check_password_hash(self.password, password)

    def get_reset_token(self, expires_sec=1800):
        s = URLSafeTimedSerializer(
            app.config['SECRET_KEY'],  # Secret key as a string
            salt=b'email-reset-salt'  # Explicitly using a byte string for salt
        )
        return s.dumps({'user_id': self.id})

    @staticmethod
    def verify_reset_token(token):
        s = URLSafeTimedSerializer(app.config['SECRET_KEY'], salt=b'email-reset-salt')
        try:
            user_id = s.loads(token, max_age=1800)['user_id']  # max_age should match expires_sec
        except Exception as e:
            return None
        return User.query.get(user_id)


class TradingBotConfig(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    api_key = db.Column(db.String(120), nullable=False)
    secret = db.Column(db.String(120), nullable=False)
    asset_name = db.Column(db.String(20), nullable=False)
    trade_size_usdt = db.Column(db.Float, nullable=False)
    indicator = db.Column(db.String(20), nullable=False)
    exchange = db.Column(db.String(20), nullable=False)

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('That username is already taken. Please choose a different one.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('That email is already registered. Please log in or use a different email.')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class RequestResetForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Request Password Reset')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is None:
            raise ValidationError('There is no account with that email. You must register first.')

class ResetPasswordForm(FlaskForm):
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Reset Password')

class OTPForm(FlaskForm):
    otp = StringField('OTP', validators=[DataRequired(), Length(6)])
    submit = SubmitField('Verify OTP')



class DashboardForm(FlaskForm):
    api_key = StringField('API Key', validators=[DataRequired()])
    secret = StringField('Secret', validators=[DataRequired()])
    asset_name = StringField('Asset Name', validators=[DataRequired()])
    trade_size_usdt = FloatField('Trade Size (USDT)', validators=[DataRequired()])
    
    # Update the indicator SelectField with the new indicators
    indicator = SelectField('Indicator', 
                            choices=[
                                ('ma', 'Moving Average'), 
                                ('stochastic', 'Stochastic'), 
                                ('macd', 'MACD'),
                                ('atr', 'ATR (Average True Range)'),
                                ('vwap', 'VWAP (Volume Weighted Average Price)'),
                                ('fibonacci', 'Fibonacci Retracement'),
                                ('rsi', 'RSI (Relative Strength Index)'),
                                ('bollinger', 'Bollinger Bands')
                            ], 
                            validators=[DataRequired()])
    
    exchange = SelectField('Exchange', 
                           choices=[
                               ('binance', 'Binance'), 
                               ('bingx', 'BingX'), 
                               ('bitget', 'Bitget'), 
                               ('bybit', 'Bybit'), 
                               ('kucoin', 'KuCoin'), 
                               ('mexc', 'MEXC'), 
                               ('okx', 'OKX')
                            ], 
                            validators=[DataRequired()])
    
    submit = SubmitField('Save Configuration')


# Function to generate and send OTP email
def send_otp_email(user):
    totp = pyotp.TOTP(user.otp_secret)
    otp = totp.now()
    logging.debug(f"Generated OTP: {otp}")
    
    msg = Message('Your OTP Code', recipients=[user.email])
    msg.body = f'Your OTP code is {otp}. It is valid for the next 10 minutes.'
    
    try:
        mail.send(msg)
        session['otp_timestamp'] = datetime.utcnow()  # Store the OTP generation time
        logging.debug("OTP email sent successfully.")
    except Exception as e:
        logging.error(f"Error sending OTP email: {e}")

# Function to send password reset email
def send_reset_email(user):
    token = user.get_reset_token()
    msg = Message('Password Reset Request', 
                  sender=app.config['MAIL_DEFAULT_SENDER'], 
                  recipients=[user.email])
    msg.body = f'''To reset your password, visit the following link:
{url_for('reset_token', token=token, _external=True)}

If you did not make this request then simply ignore this email and no changes will be made.
'''
    try:
        mail.send(msg)
        logging.debug("Password reset email sent successfully.")
    except Exception as e:
        logging.error(f"Error sending password reset email: {e}")

# Function to return the subscription plans
def get_plans():
    return {
        "1_month": {"amount": "900", "duration": timedelta(days=30)},
        "3_months": {"amount": "2499", "duration": timedelta(days=90)},
        "6_months": {"amount": "4999", "duration": timedelta(days=180)},
        "1_year": {"amount": "8499", "duration": timedelta(days=365)},
    }

# Function to generate PayU hash
def generate_payu_hash(data):
    hash_string = f"{data['key']}|{data['txnid']}|{data['amount']}|{data['productinfo']}|{data['firstname']}|{data['email']}|||||||||||{PAYU_SALT}"
    return hashlib.sha512(hash_string.encode('utf-8')).hexdigest()

# Route to register new users
@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    
    form = RegistrationForm()

    if form.validate_on_submit():  # If the form is valid
        hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256', salt_length=16)

        # Temporarily store user data in session
        session['temp_user'] = {
            'username': form.username.data,
            'email': form.email.data,
            'password': hashed_password,
            'otp_secret': pyotp.random_base32()
        }

        temp_user = session['temp_user']
        user = User(username=temp_user['username'], email=temp_user['email'], 
                    password=temp_user['password'], otp_secret=temp_user['otp_secret'])
        send_otp_email(user)

        flash('An OTP has been sent to your email. Please enter it to complete the registration.', 'info')
        return redirect(url_for('verify_otp'))
    
    # No need to manually flash form errors here; WTForms will handle it.

    return render_template('register.html', form=form)


# Route to verify OTP
@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    temp_user = session.get('temp_user')
    if not temp_user:
        flash('Session expired or no registration data found. Please register again.', 'danger')
        return redirect(url_for('register'))

    form = OTPForm()
    if form.validate_on_submit():
        # Retrieve OTP timestamp
        otp_timestamp = session.get('otp_timestamp')
        
        # Convert otp_timestamp to naive if it is aware
        if otp_timestamp and otp_timestamp.tzinfo is not None:
            otp_timestamp = otp_timestamp.replace(tzinfo=None)
        
        # Check if OTP has expired (ensure both datetime objects are naive)
        if otp_timestamp and datetime.utcnow() > otp_timestamp + timedelta(minutes=10):
            flash('Your OTP has expired. Please request a new one.', 'danger')
            return redirect(url_for('verify_otp'))

        totp = pyotp.TOTP(temp_user['otp_secret'])
        
        # Increase valid_window to 20 (allow 10 minutes window)
        if totp.verify(form.otp.data, valid_window=20):  
            user = User(username=temp_user['username'], email=temp_user['email'], 
                        password=temp_user['password'], otp_secret=temp_user['otp_secret'])
            db.session.add(user)
            db.session.commit()
            session.pop('temp_user', None)
            session.pop('otp_timestamp', None)  # Clear the OTP timestamp
            
            login_user(user)
            flash('Your account has been created and verified successfully.', 'success')
            return redirect(url_for('pricing'))
        else:
            flash('Invalid or expired OTP.', 'danger')
            return redirect(url_for('verify_otp'))
    
    return render_template('verify_otp.html', form=form)


# Route to resend OTP
@app.route('/resend_otp', methods=['GET', 'POST'])
def resend_otp():
    temp_user = session.get('temp_user')
    if not temp_user:
        flash('Session expired or no registration data found. Please register again.', 'danger')
        return redirect(url_for('register'))
    
    user = User(username=temp_user['username'], email=temp_user['email'], 
                password=temp_user['password'], otp_secret=temp_user['otp_secret'])
    send_otp_email(user)
    flash('A new OTP has been sent to your email.', 'info')
    return redirect(url_for('verify_otp'))

# Route to display the pricing options
@app.route('/pricing')
@login_required
def pricing():
    return render_template('pricing.html')

# Route to handle PayU payment
@app.route('/payu_payment/<plan>', methods=['POST'])
@login_required
def payu_payment(plan):
    # Get the plans dictionary
    plans = get_plans()

    if plan not in plans:
        flash('Invalid plan selected.', 'danger')
        return redirect(url_for('pricing'))

    # Generate PayU transaction ID
    txnid = f"txn_{datetime.utcnow().timestamp()}_{current_user.id}"

    # Data to send to PayU
    data = {
        "key": PAYU_KEY,
        "txnid": txnid,
        "amount": plans[plan]["amount"],
        "productinfo": plan.replace("_", " ").title(),
        "firstname": current_user.username,
        "email": current_user.email,
        "phone": "9999999999",  # Replace with the user's phone number if available
        "surl": url_for('payu_success', plan=plan, _external=True),
        "furl": url_for('payu_failure', _external=True),
        "hash": generate_payu_hash({
            "key": PAYU_KEY,
            "txnid": txnid,
            "amount": plans[plan]["amount"],
            "productinfo": plan.replace("_", " ").title(),
            "firstname": current_user.username,
            "email": current_user.email,
        })
    }

    return render_template('payu_redirect.html', data=data, payu_url=PAYU_URL)

# Route to handle PayU success
@app.route('/payu_success/<plan>', methods=['POST'])
@login_required
def payu_success(plan):
    plans = get_plans()
    current_user.subscription_plan = plan.replace('_', ' ')
    current_user.subscription_start = datetime.utcnow()
    current_user.subscription_end = datetime.utcnow() + plans[plan]["duration"]
    current_user.subscription_active = True
    db.session.commit()

    flash(f'You have successfully subscribed to the {plan.replace("_", " ").title()} plan!', 'success')
    return redirect(url_for('home'))

# Route to handle PayU failure
@app.route('/payu_failure', methods=['POST'])
@login_required
def payu_failure():
    flash('Payment failed. Please try again.', 'danger')
    return redirect(url_for('pricing'))

# Scheduled job to check for expired subscriptions
def check_expired_subscriptions():
    with app.app_context():
        now = datetime.utcnow()
        expired_users = User.query.filter(User.subscription_active == True, User.subscription_end <= now).all()
        for user in expired_users:
            user.subscription_active = False
            db.session.commit()
            logging.debug(f"Subscription expired for user {user.username}")

# Set up scheduler to run the subscription expiration check daily
scheduler = BackgroundScheduler(timezone=pytz.utc)
scheduler.add_job(check_expired_subscriptions, 'interval', days=1)
scheduler.start()

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():  # WTForms handles form validation
        user = User.query.filter_by(email=form.email.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('home'))
        else:
            # Flash authentication-specific error
            flash('Invalid email or password', 'danger')

    # No need to flash form validation errors; WTForms will handle `form.errors`
    return render_template('login.html', form=form)




# Route to log out users
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

# Route for Google login
@app.route('/login/google')
def google_login():
    nonce = generate_token()
    session['nonce'] = nonce
    redirect_uri = url_for('google_callback', _external=True)
    return google.authorize_redirect(redirect_uri, nonce=nonce)

# Callback route for Google login
@app.route('/callback')
def google_callback():
    try:
        token = google.authorize_access_token()
        nonce = session.pop('nonce', None)
        user_info = google.parse_id_token(token, nonce=nonce)
        
        username = user_info.get('name', user_info.get('email', 'Unknown'))
        email = user_info.get('email')
        
        user = User.query.filter_by(email=email).first()
        
        if user is None:
            user = User(username=username, email=email, password='')
            db.session.add(user)
            db.session.commit()
        
        login_user(user)
        
        return redirect(url_for('home'))
    
    except Exception as e:
        logging.error(f"Error during Google login: {e}")
        flash(f'Error during Google login: {str(e)}', 'danger')
        return redirect(url_for('login'))

# Route to request password reset
@app.route('/reset_password', methods=['GET', 'POST'])
def reset_request():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RequestResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        send_reset_email(user)
        flash('An email has been sent with instructions to reset your password.', 'info')
        return redirect(url_for('login'))
    return render_template('reset_request.html', title='Reset Password', form=form)

# Route to reset password
@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_token(token):
    user = User.verify_reset_token(token)
    if user is None:
        flash('That is an invalid or expired token', 'warning')
        return redirect(url_for('reset_request'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256', salt_length=16)
        user.password = hashed_password
        db.session.commit()
        flash('Your password has been updated! You are now able to log in', 'success')
        return redirect(url_for('login'))
    return render_template('reset_token.html', title='Reset Password', form=form, token=token)

@app.route('/dashboard')
@login_required
def dashboard():
    # Fetch the user's trading bot configuration
    config = TradingBotConfig.query.filter_by(user_id=current_user.id).first()

    # Determine the user's bot status
    user_bot_status = 'running' if current_user.id in active_bots else 'stopped'

    # Render the dashboard with the necessary context
    return render_template(
        'dashboard.html',
        config=config,
        bot_status=bot_status,
        user_bot_status=user_bot_status  # Pass this to the template
    )



# app.py (start_bot route)
@app.route('/start_bot', methods=['POST'])
@login_required
def start_bot():
    try:
        # Fetch user configuration
        config = TradingBotConfig.query.filter_by(user_id=current_user.id).first()
        if not config:
            flash('Please configure your bot settings first.', 'danger')
            return redirect(url_for('dashboard'))

        # Validate trade size
        if config.trade_size_usdt < 30:
            flash('Trade size must be at least 30 USDT.', 'danger')
            return redirect(url_for('dashboard'))

        # Convert asset_name into a list if it's a comma-separated string
        assets = config.asset_name
        if isinstance(assets, str):
            assets = [asset.strip() for asset in assets.split(',')]

        # Initialize and start the bot with multiple assets
        bot = TradingBot(
            api_key=config.api_key,
            secret=config.secret,
            assets=assets,  # Pass the assets as a list
            trade_size_usdt=config.trade_size_usdt,
            indicator=config.indicator,
            exchange=config.exchange
        )
        active_bots[current_user.id] = bot

        # Start the bot in a new event loop
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_in_executor(None, asyncio.run, bot.start_trading())

        flash('Trading bot started successfully!', 'success')

    except ccxt.NetworkError as e:
        error_message = f"Network error: {str(e)}"
        logging.error(error_message)
        flash('Network error. Check your internet connection.', 'danger')

    except ccxt.ExchangeError as e:
        if "Invalid symbol" in str(e):
            error_message = "Invalid asset name provided. Please check your asset configuration."
            logging.error(error_message)
            flash(error_message, 'danger')
        elif "Incorrect apiKey" in str(e):
            error_message = "Incorrect API key provided. Please check your API key and try again."
            logging.error(error_message)
            flash(error_message, 'danger')
        else:
            error_message = f"Exchange error: {str(e)}"
            logging.error(error_message)
            flash(f'Exchange error: {error_message}', 'danger')

    except ValueError as e:
        logging.error(f"Validation error: {str(e)}")
        flash(f'Error: {str(e)}', 'danger')

    except Exception as e:
        error_message = f"Unexpected error: {str(e)}"
        logging.error(error_message)
        flash(f'An unexpected error occurred: {str(e)}', 'danger')

    return redirect(url_for('dashboard'))


@app.route('/stop_bot', methods=['POST'])
@login_required
def stop_bot():
    try:
        bot = active_bots.get(current_user.id)  # Retrieve the bot instance
        if not bot:
            flash('No bot is currently running.', 'danger')
            return redirect(url_for('dashboard'))

        bot.stop()  # Stop the bot
        del active_bots[current_user.id]  # Remove bot instance from dictionary

        flash('Trading bot stopped successfully!', 'success')

    except Exception as e:
        # Handle unexpected errors
        error_message = f"An error occurred while stopping the bot: {str(e)}"
        logging.error(error_message)
        flash(f'An error occurred while stopping the bot: {str(e)}', 'danger')

    return redirect(url_for('dashboard'))

# Route to edit the bot configuration
@app.route('/edit_config', methods=['GET', 'POST'])
@login_required
def edit_config():
    config = TradingBotConfig.query.filter_by(user_id=current_user.id).first()
    if not config:
        flash('Please configure your bot settings first.', 'danger')
        return redirect(url_for('dashboard'))

    form = DashboardForm(obj=config)  # Populate form with current config data

    if form.validate_on_submit():
        config.api_key = form.api_key.data
        config.secret = form.secret.data
        config.asset_name = form.asset_name.data
        config.trade_size_usdt = form.trade_size_usdt.data
        config.indicator = form.indicator.data
        config.exchange = form.exchange.data
        db.session.commit()
        flash('Configuration updated successfully!', 'success')
        return redirect(url_for('dashboard'))

    return render_template('edit_config.html', form=form)  # Ensure you have a separate template for editing.
@app.route('/policy')
def policy():
    return render_template('policy.html')

# Home route
@app.route('/')
def home():
    return render_template('index.html')


if __name__ == '__main__':
    app.run(debug=True)
