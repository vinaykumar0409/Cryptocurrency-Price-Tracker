import pandas as pd
from datetime import datetime, timedelta
from sqlalchemy import inspect
from flask import Flask, render_template, jsonify, request, flash, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_required, current_user, UserMixin, login_user, logout_user
import requests
import os
from werkzeug.security import check_password_hash, generate_password_hash
from flask_migrate import Migrate
import random

app = Flask(__name__)

DB_USER = 'root'
DB_PASSWORD = 'jhNSNYm37CaH!!k7'
DB_HOST = os.environ.get("DB_HOST", "localhost")
app.config['SQLALCHEMY_DATABASE_URI'] = f'mysql+pymysql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}/crypto_tracker'  
app.config['SECRET_KEY'] = 'your_secret_key_here'  # Replace with a real secret key

try:
    db = SQLAlchemy(app)
except Exception as e:
    print(f"Error connecting to the database: {e}")

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# User model for user logins
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)  # Store hashed passwords
    watchlist = db.relationship('Watchlist', backref='user', lazy=True)

# MarketPrices model for storing market prices
# MarketPrices model for storing market prices
class MarketPrices(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    symbol = db.Column(db.String(10), nullable=False)
    current_price = db.Column(db.Float, nullable=False)
    price_change_percentage_1h = db.Column(db.Float, nullable=False)
    price_change_percentage_24h = db.Column(db.Float, nullable=False)
    price_change_percentage_7d = db.Column(db.Float, nullable=False)
    total_volume = db.Column(db.Float, nullable=False)
    market_cap = db.Column(db.Float, nullable=False)
    market_cap_rank = db.Column(db.Integer, nullable=False)
    sparkline_7d = db.Column(db.Text, nullable=True)  # Store sparkline data as text
    last_updated = db.Column(db.String(50), nullable=False)  # Specify length for VARCHAR

# Watchlist model for each user's watchlist
class Watchlist(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    crypto_symbol = db.Column(db.String(10), nullable=False)

# Helper functions
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    return render_template('index.html')

COINGECKO_API_URL = "https://api.coingecko.com/api/v3/coins/markets"

def fetch_crypto_data(limit=10):
    params = {
        "vs_currency": "usd",
        "order": "market_cap_desc",
        "per_page": limit,
        "page": 1,
        "sparkline": 'true',
        "price_change_percentage": "1h,24h,7d"
    }
    
    response = requests.get(COINGECKO_API_URL, params=params)
    response.raise_for_status()
    return response.json()

def store_crypto_data(data):
    for coin in data:
        market_price = MarketPrices(
            id = coin['id'],
            symbol=coin['symbol'],
            current_price=coin['current_price'],
            price_change_percentage_1h=coin['price_change_percentage_1h_in_currency'],
            price_change_percentage_24h=coin['price_change_percentage_24h_in_currency'],
            price_change_percentage_7d=coin['price_change_percentage_7d_in_currency'],
            total_volume=coin['total_volume'],
            market_cap=coin['market_cap'],
            market_cap_rank=coin['market_cap_rank'],
            sparkline_7d=str(coin['sparkline_in_7d']['price']),
            last_updated=coin['last_updated']
        )
        existing_market_price = MarketPrices.query.filter_by(symbol=coin['symbol']).first()
        if existing_market_price:
            existing_market_price.current_price = coin['current_price']
            existing_market_price.price_change_percentage_1h = coin['price_change_percentage_1h_in_currency']
            existing_market_price.price_change_percentage_24h = coin['price_change_percentage_24h_in_currency']
            existing_market_price.price_change_percentage_7d = coin['price_change_percentage_7d_in_currency']
            existing_market_price.total_volume = coin['total_volume']
            existing_market_price.market_cap = coin['market_cap']
            existing_market_price.market_cap_rank = coin['market_cap_rank']
            existing_market_price.sparkline_7d = str(coin['sparkline_in_7d']['price'])
            existing_market_price.last_updated = coin['last_updated']
        else:
            db.session.add(market_price)  # Add new record if not exist
    db.session.commit()

@app.route('/prices')
def get_crypto_data():
    if db.session.is_active:
        print("Database session is active.")
    else:
        print("Database session is not active.")

    # Fetch cryptocurrency data from CoinGecko API
    result = db.session.query(MarketPrices.last_updated).order_by(MarketPrices.last_updated.desc()).first()
    
    if result is None or datetime.strptime(result[0], "%Y-%m-%dT%H:%M:%S.%fZ") < datetime.utcnow() - timedelta(minutes=15):
        print("Fetching new data from CoinGecko API...")
        data = fetch_crypto_data()
        store_crypto_data(data)
    else:
        print("Using stored data...")
        
    # Retrieve stored data for rendering
    query = MarketPrices.query.distinct().order_by(MarketPrices.market_cap_rank.asc())
    result = query.all()

    # Create charts for each cryptocurrency's sparkline data
    charts = {}
    for crypto in result:
        charts[crypto.symbol] = create_chart(crypto.sparkline_7d)

    return render_template('trading.html', cryptos=result, charts=charts)

def create_chart(sparkline_data):
    import matplotlib.pyplot as plt
    import io
    import base64

    plt.figure(figsize=(5, 2))
    plt.plot(eval(sparkline_data))
    plt.axis('off')
    
    buffer = io.BytesIO()
    plt.savefig(buffer, format='png', bbox_inches='tight', pad_inches=0)
    buffer.seek(0)
    image = base64.b64encode(buffer.getvalue()).decode('utf-8')
    plt.close()
    
    return f'<img src="data:image/png;base64,{image}" alt="7d chart">'

@app.route('/watchlist')
@login_required
def watchlist():   
    # Retrieve stored data for rendering
    query = Watchlist.query.distinct()
    result = query.all()

    # Create charts for each cryptocurrency's sparkline data
    charts = {}
    cryptos_details = []  # List to hold details of each cryptocurrency

    for watch_item in result:
        crypto = MarketPrices.query.filter_by(symbol=watch_item.crypto_symbol).first()  # Fetch details from MarketPrices
        if crypto:
            charts[crypto.symbol] = create_chart(crypto.sparkline_7d)
            cryptos_details.append(crypto)  # Add the crypto details to the list

    return render_template('watchlist.html', cryptos=cryptos_details, charts=charts)

@app.route('/add_to_watchlist', methods=['POST'])
@login_required
def add_to_watchlist():
    data = request.get_json()
    user_id = data.get('user_id')
    symbol = data.get('symbol')

    # Check if the cryptocurrency is already in the watchlist
    existing_watchlist_item = Watchlist.query.filter_by(user_id=user_id, crypto_symbol=symbol).first()
    if existing_watchlist_item:
        return jsonify({'message': 'This cryptocurrency is already in your watchlist.'}), 400

    # Create a new watchlist entry
    new_watchlist_item = Watchlist(user_id=user_id, crypto_symbol=symbol)  # Corrected to Watchlist
    db.session.add(new_watchlist_item)
    db.session.commit()

    return jsonify({'message': 'Cryptocurrency added to watchlist!'}), 200


@app.route('/crypto/<string:symbol>')
def crypto_detail(symbol):
    crypto = MarketPrices.query.filter_by(symbol=symbol).first()
    chart = create_chart(crypto.sparkline_7d)
    if crypto:
        return render_template('crypto_detail.html', crypto=crypto, chart=chart)
    else:
        flash('Cryptocurrency not found!', 'danger')
        return redirect(url_for('get_crypto_data'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            flash('Logged in successfully.', 'success')
            return redirect(url_for('get_crypto_data'))
        else:
            flash('Invalid username or password', 'error')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        # Add more fields as necessary
        user = User.query.filter_by(username=username).first()
        if user:
            flash('Username already exists', 'error')
        else:
            new_user = User(username=username, password=generate_password_hash(password))
            db.session.add(new_user)
            db.session.commit()
            flash('Registered successfully', 'success')
            return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/forgot_password')
def forgot_password():
    return render_template('forgot_password.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()  # This will log out the user
    return redirect(url_for('index'))  

should_logout = True

@app.before_request
def before_request():
    global should_logout
    if should_logout and current_user.is_authenticated:
        logout_user()  # Log out the user if they are logged in
        should_logout = False 

# Add this function to create tables
def create_tables():
    try:
        with app.app_context():
            db.create_all()
            print("Tables created successfully.")
            # Check if the tables exist using the inspect module
            inspector = inspect(db.engine)
            print("Existing tables:", inspector.get_table_names())
    except Exception as e:
        print(f"Error creating tables: {e}")


if __name__ == '__main__':
    create_tables()  # Ensure tables are created before running the app
    app.run(debug=True)