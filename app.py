
from flask import Flask, request, jsonify, redirect, url_for, render_template
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS
from db import db, User
import os

app = Flask(__name__)

# ✅ TEMPORARY: Allow all origins to debug CORS
CORS(app, origins="*", supports_credentials=True)

# ✅ Config
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SECRET_KEY'] = 'super-secret-key'
app.config['SESSION_COOKIE_SAMESITE'] = "None"
app.config['SESSION_COOKIE_SECURE'] = True

# ✅ Init DB and create tables
db.init_app(app)
with app.app_context():
    db.create_all()

# ✅ Login Manager Setup
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ✅ ROUTES

@app.route('/')
def index():
    return "Backend is running ✅"

@app.route('/signup', methods=['POST'])
def signup():
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')

        if User.query.filter_by(email=email).first():
            return jsonify({"error": "Email already registered"}), 400

        hashed_pw = generate_password_hash(password)
        new_user = User(email=email, password=hashed_pw)
        db.session.add(new_user)
        db.session.commit()

        return jsonify({"message": "Signup successful"}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500
 
@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')

        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return jsonify({"message": "Login successful"}), 200

        return jsonify({"error": "Invalid credentials"}), 401

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/dashboard')
@login_required
def dashboard():
    return f"Welcome {current_user.email}"

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

# ✅ Run App
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=10000)
