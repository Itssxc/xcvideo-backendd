from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, login_user
from flask_cors import CORS
import os

app = Flask(__name__)

CORS(app, resources={r"/*": {"origins": [
    "https://xcvideo-frontendnew.vercel.app",
    "https://xcvideo-frontendnew-*.vercel.app"
]}}, supports_credentials=True)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SECRET_KEY'] = 'super-secret-key'
app.config['SESSION_COOKIE_SAMESITE'] = "None"
app.config['SESSION_COOKIE_SECURE'] = True

db = SQLAlchemy(app)
login_manager = LoginManager(app)

# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)

with app.app_context():
    db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    if User.query.filter_by(email=data['email']).first():
        return jsonify({"error": "Email already registered"}), 400
    user = User(email=data['email'], password=generate_password_hash(data['password']))
    db.session.add(user); db.session.commit()
    resp = jsonify({"message": "Signup successful"}); resp.headers.add("Access-Control-Allow-Credentials", "true")
    return resp, 200

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(email=data['email']).first()
    if user and check_password_hash(user.password, data['password']):
        login_user(user)
        resp = jsonify({"message": "Login successful"}); resp.headers.add("Access-Control-Allow-Credentials", "true")
        return resp, 200
    return jsonify({"error": "Invalid credentials"}), 401

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000)
