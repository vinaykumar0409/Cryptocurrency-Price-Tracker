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
import boto3
from botocore.exceptions import ClientError
import decimal

application = Flask(__name__)

DYNAMODB_TABLE_USERS = 'Users'
DYNAMODB_TABLE_MARKET_PRICES = 'MarketPrices'
DYNAMODB_TABLE_WATCHLIST = 'Watchlist'
application.config['SECRET_KEY'] = 'your_secret_key_here'  # Replace with a real secret key

# Initialize Boto3 DynamoDB resource
dynamodb = boto3.resource('dynamodb', region_name='us-east-1')


login_manager = LoginManager()
login_manager.init_app(application)
login_manager.login_view = 'login'

# User model for user logins
class User(UserMixin):
    def __init__(self, username, password):
        self.id = username  # Use username as the unique identifier
        self.username = username
        self.password = password

# Helper function to get user from DynamoDB
def get_user(username):
    table = dynamodb.Table(DYNAMODB_TABLE_USERS)
    try:
        response = table.get_item(Key={'username': username})
        return response.get('Item')
    except ClientError as e:
        print(e.response['Error']['Message'])
        return None

@login_manager.user_loader
def load_user(username):  # Change user_id to username
    table = dynamodb.Table(DYNAMODB_TABLE_USERS)
    try:
        response = table.get_item(Key={'username': username})  # Use username as the key
        item = response.get('Item')
        if item:
            return User(item['username'], item['password'])  # No need for id
    except ClientError as e:
        print(e.response['Error']['Message'])
    return None

@application.route('/')
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
    table = dynamodb.Table(DYNAMODB_TABLE_MARKET_PRICES)
    for coin in data:
        try:
            table.put_item(Item={
                'symbol': coin['symbol'],
                'current_price': decimal.Decimal(coin['current_price']).quantize(decimal.Decimal('0.00')),  # Specify precision
                'price_change_percentage_1h': decimal.Decimal(coin['price_change_percentage_1h_in_currency']).quantize(decimal.Decimal('0.00')),  # Specify precision
                'price_change_percentage_24h': decimal.Decimal(coin['price_change_percentage_24h_in_currency']).quantize(decimal.Decimal('0.00')),  # Specify precision
                'price_change_percentage_7d': decimal.Decimal(coin['price_change_percentage_7d_in_currency']).quantize(decimal.Decimal('0.00')),  # Specify precision
                'total_volume': decimal.Decimal(coin['total_volume']).quantize(decimal.Decimal('0')),  # Specify precision
                'market_cap': decimal.Decimal(coin['market_cap']).quantize(decimal.Decimal('0')),  # Specify precision
                'market_cap_rank': coin['market_cap_rank'],  # Assuming this is an integer
                'sparkline_7d': str(coin['sparkline_in_7d']['price']),
                'last_updated': coin['last_updated']
            })
        except ClientError as e:
            print(e.response['Error']['Message'])

@application.route('/prices')
def get_crypto_data():
    # Fetch cryptocurrency data from CoinGecko API
    data = fetch_crypto_data()
    store_crypto_data(data)

    # Retrieve stored data for rendering
    table = dynamodb.Table(DYNAMODB_TABLE_MARKET_PRICES)
    response = table.scan()
    result = response['Items']

    # Create charts for each cryptocurrency's sparkline data
    charts = {}
    for crypto in result:
        charts[crypto['symbol']] = create_chart(crypto['sparkline_7d'])

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

@application.route('/watchlist')
@login_required
def watchlist():   
    # Retrieve stored data for the logged-in user
    user_id = current_user.id  # Get the current user's ID
    table = dynamodb.Table(DYNAMODB_TABLE_WATCHLIST)
    
    # Scan the table and filter for the current user's watchlist items
    response = table.scan(FilterExpression='user_id = :user_id', ExpressionAttributeValues={':user_id': user_id})
    result = response['Items']

    # Create charts for each cryptocurrency's sparkline data
    charts = {}
    cryptos_details = []  # List to hold details of each cryptocurrency

    for watch_item in result:
        crypto = get_market_price(watch_item['crypto_symbol'])  # Fetch details from MarketPrices
        if crypto:
            charts[crypto['symbol']] = create_chart(crypto['sparkline_7d'])
            cryptos_details.append(crypto)  # Add the crypto details to the list

    return render_template('watchlist.html', cryptos=cryptos_details, charts=charts)

def get_market_price(symbol):
    table = dynamodb.Table(DYNAMODB_TABLE_MARKET_PRICES)
    try:
        response = table.get_item(Key={'symbol': symbol})
        return response.get('Item')
    except ClientError as e:
        print(e.response['Error']['Message'])
        return None
    
@application.route('/refresh_prices', methods=['POST'])
@login_required
def refresh_prices():
    # Fetch cryptocurrency data from CoinGecko API
    data = fetch_crypto_data()
    store_crypto_data(data)  # Update the MarketPrices table

    return jsonify({'message': 'Prices updated successfully!'}), 200

@application.route('/add_to_watchlist', methods=['POST'])
@login_required
def add_to_watchlist():
    
    data = request.get_json()
    if not data or 'user_id' not in data or 'symbol' not in data:
        print('data not available')
        return jsonify({'message': 'Invalid input data.'}), 400
    user_id = data.get('user_id')
    symbol = data.get('symbol')

    # Check if the cryptocurrency is already in the watchlist
    table = dynamodb.Table(DYNAMODB_TABLE_WATCHLIST)
    
    try:
        existing_watchlist_item = table.get_item(Key={'crypto_symbol': symbol, 'user_id': user_id}).get('Item')
    except ClientError as e:
        print(f"Error fetching item: {e.response['Error']['Message']}")
        return jsonify({'message': 'Error checking watchlist.'}), 500

    if existing_watchlist_item:
        print(existing_watchlist_item)
        return jsonify({'message': 'This cryptocurrency is already in your watchlist.'}), 400

    # Create a new watchlist entry
    new_watchlist_item = {
        'user_id': user_id,
        'crypto_symbol': symbol
    }
    table.put_item(Item=new_watchlist_item)

    return jsonify({'message': 'Cryptocurrency added to watchlist!'}), 200

@application.route('/remove_from_watchlist', methods=['POST'])
@login_required
def remove_from_watchlist():
    data = request.get_json()
    user_id = data.get('user_id')
    symbol = data.get('symbol')

    # Remove the cryptocurrency from the watchlist
    table = dynamodb.Table(DYNAMODB_TABLE_WATCHLIST)
    
    try:
        # Delete the item using user_id and crypto_symbol as the key
        table.delete_item(
            Key={
                'user_id': user_id,
                'crypto_symbol': symbol
            }
        )
        return jsonify({'message': 'Cryptocurrency removed from watchlist!'}), 200
    except ClientError as e:
        print(f"Error removing item: {e.response['Error']['Message']}")
        return jsonify({'message': 'Error removing from watchlist.'}), 500


@application.route('/crypto/<string:symbol>')
def crypto_detail(symbol):
    crypto = get_market_price(symbol)
    if crypto:
        chart = create_chart(crypto['sparkline_7d'])
        return render_template('crypto_detail.html', crypto=crypto, chart=chart)
    else:
        flash('Cryptocurrency not found!', 'danger')
        return redirect(url_for('get_crypto_data'))

@application.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = get_user(username)
        if user and check_password_hash(user['password'], password):
            login_user(User(user['username'], user['password']))  # Use username instead of id
            flash('Logged in successfully.', 'success')
            return redirect(url_for('get_crypto_data'))
        else:
            flash('Invalid username or password', 'error')
    return render_template('login.html')

@application.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        # Add more fields as necessary
        table = dynamodb.Table(DYNAMODB_TABLE_USERS)
        existing_user = table.get_item(Key={'username': username}).get('Item')
        if existing_user:
            flash('Username already exists', 'error')
        else:
            new_user = {
                'username': username,
                'email': email,
                'password': generate_password_hash(password)
            }
            table.put_item(Item=new_user)
            flash('Registered successfully', 'success')
            return redirect(url_for('login'))
    return render_template('register.html')

@application.route('/forgot_password')
def forgot_password():
    return render_template('forgot_password.html')

@application.route('/logout')
@login_required
def logout():
    logout_user()  # This will log out the user
    return redirect(url_for('index'))  

@application.before_request
def before_request():
    if current_user.is_authenticated:
        # You can add any pre-request logic here
        pass
@application.route('/logout_startup')
def logout_startup():
    if current_user.is_authenticated:
        logout_user()  # Log out the user if they are logged in
    return "User logged out if they were logged in."

should_logout = True

@application.before_request
def before_request():
    global should_logout
    if should_logout and current_user.is_authenticated:
        logout_user()  # Log out the user if they are logged in
        should_logout = False  # Reset the flag after logging out

if __name__ == '__main__':
    application.run(host='0.0.0.0', port=5000)
