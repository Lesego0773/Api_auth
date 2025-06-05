from flask import Flask, request, jsonify
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy
import jwt
import datetime 
import os
from dotenv import load_dotenv


load_dotenv()  # Load environment variables from .env file

app = Flask(__name__)  # Initialize Flask app
bcrypt = Bcrypt(app)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'  # SQLite database for simplicity
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'Kabelo@2580')  # Default fallback

db = SQLAlchemy(app)  # Initializing SQLAlchemy

# Database model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

# Create the database tables
with app.app_context():
    db.create_all()


# In-memory database substitute
users_db = {}

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    name = data.get('name')
    email = data.get('email')
    password = data.get('password')

    if not name or not email or not password:
        return jsonify({'message': 'Missing fields'}), 400

    if email in users_db:
        return jsonify({'message': 'User already exists'}), 400

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    users_db[email] = {
        'name': name,
        'email': email,
        'password': hashed_password
    }

    token = jwt.encode({
        'email': email,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    }, app.config['SECRET_KEY'], algorithm='HS256')

    return jsonify({
        'message': 'User registered successfully',
        'token': token
    }), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({'message': 'Email and password are required!'}), 400

    user = users_db.get(email)
    if not user:
        return jsonify({'message': 'User not found!'}), 404

    if not bcrypt.check_password_hash(user['password'], password):
        return jsonify({'message': 'Invalid password!'}), 401

    token = jwt.encode({
        'email': email,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    }, app.config['SECRET_KEY'], algorithm='HS256')

    return jsonify({
        'message': 'Login successful',
        'token': token
    }), 200

@app.route('/protected', methods=['POST'])
def protected():
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'message': 'Token is missing!'}), 401
    try:
        data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        email = data['email']
        return jsonify({'message': f'Welcome {email}! This is a protected route.'}), 200
    except jwt.ExpiredSignatureError:
        return jsonify({'message': 'Token has expired!'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'message': 'Invalid token!'}), 401

@app.route('/profile', methods=['POST'])
def profile():
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'message': 'Token is missing!'}), 401
    try:
        data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        email = data['email']
        user = users_db.get(email)
        if not user:
            return jsonify({'message': 'User not found!'}), 404
        return jsonify({
            'name': user['name'],
            'email': user['email']
        }), 200
    except jwt.ExpiredSignatureError:
        return jsonify({'message': 'Token has expired!'}), 401
    
    except jwt.InvalidTokenError:
        return jsonify({'message': 'Invalid token!'}), 401 
        
        
#Update profile
@app.route('/update_profile', methods=['POST'])
def update_profile():
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'message': 'Token is missing!'}), 401
    try:
        data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        email = data['email']
        user = users_db.get(email)
        if not user:
            return jsonify({'message': 'User not found!'}), 404
        
        new_name = request.json.get('name')
        new_email = request.json.get('email')
        
        if new_name:
            user['name'] = new_name
        if new_email:
            if new_email in users_db and new_email != email:
                return jsonify({'message': 'Email already exists!'}), 400
            del users_db[email]  # Remove old email
            user['email'] = new_email
            users_db[new_email] = user  # Add with new email
        
        return jsonify({'message': 'Profile updated successfully', 'user': user}), 200
    except jwt.ExpiredSignatureError:
        return jsonify({'message': 'Token has expired!'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'message': 'Invalid token!'}), 401



if __name__ == '__main__':
    app.run(debug=True)
