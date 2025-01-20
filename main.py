from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError
import bcrypt
import uuid

app = Flask(__name__)

# Configure the local database connection
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqlconnector://root:your_password@localhost/your_database_name'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Define the User model
class User(db.Model):
    __tablename__ = 'users'
    uid = db.Column(db.Integer, primary_key=True, autoincrement=True)
    firstname = db.Column(db.String(255), nullable=False)
    lastname = db.Column(db.String(255), nullable=False)
    username = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    user_key = db.Column(db.String(36), unique=True, nullable=False)

# Initialize the database
@app.before_request
def create_tables():
    db.create_all()

# Sign-up endpoint
@app.route('/signup', methods=['POST'])
def signup():
    try:
        data = request.json
        firstname = data.get('firstname')
        lastname = data.get('lastname')
        username = data.get('username')
        password = data.get('password')

        # Validate input
        if not all([firstname, lastname, username, password]):
            return jsonify({'error': 'All fields are required'}), 400

        # Hash the password
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        # Generate a UUID for the user_key
        user_key = str(uuid.uuid4())

        # Save the user to the database
        new_user = User(
            firstname=firstname,
            lastname=lastname,
            username=username,
            password=hashed_password,
            user_key=user_key
        )
        db.session.add(new_user)
        db.session.commit()

        return jsonify({'user_key': user_key}), 201
    except IntegrityError:
        db.session.rollback()
        return jsonify({'error': 'Username already exists'}), 409
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Login endpoint
@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.json
        username = data.get('username')
        password = data.get('password')

        # Validate input
        if not all([username, password]):
            return jsonify({'error': 'Both username and password are required'}), 400

        # Fetch the user from the database
        user = User.query.filter_by(username=username).first()

        if user and bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
            return jsonify({'user_key': user.user_key}), 200
        else:
            return jsonify({'error': 'Invalid username or password'}), 401
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
