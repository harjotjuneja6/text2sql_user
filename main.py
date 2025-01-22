from flask import Flask, request, jsonify
import mysql.connector
from mysql.connector import Error
import uuid
import hashlib

app = Flask(__name__)

# Database configuration
DB_CONFIG = {
    "host": "localhost",
    "user": "root",
    "password": "admin",
    "database": "mysql",
    "auth_plugin": 'mysql_native_password'
}

def init_db():
    try:
        with mysql.connector.connect(**DB_CONFIG) as connection:
            with connection.cursor() as cursor:
                # Create users table if it doesn't exist
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS users (
                        firstname VARCHAR(255) NOT NULL,
                        lastname VARCHAR(255) NOT NULL,
                        username VARCHAR(255) UNIQUE NOT NULL,
                        password VARCHAR(255) NOT NULL,
                        user_key VARCHAR(36) UNIQUE NOT NULL,
                        db_type VARCHAR(50) NOT NULL,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                connection.commit()
    except Error as e:
        print(f"Database initialization error: {e}")

def hash_password(password):
    """Hash the password using SHA-256"""
    return hashlib.sha256(password.encode()).hexdigest()

@app.route('/signup', methods=['POST'])
def signup():
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['firstname', 'lastname', 'username', 'password', 'db_type']
        for field in required_fields:
            if field not in data:
                return jsonify({
                    'error': f'Missing required field: {field}'
                }), 400

        # Extract data
        firstname = data['firstname']
        lastname = data['lastname']
        username = data['username']
        password = data['password']
        db_type = data['db_type']
        
        # Validate db_type (optional)
        valid_db_types = ['mysql', 'postgresql', 'mongodb', 'sqlite']
        if db_type.lower() not in valid_db_types:
            return jsonify({
                'error': f'Invalid db_type. Must be one of: {", ".join(valid_db_types)}'
            }), 400
        
        # Generate user_key
        user_key = str(uuid.uuid4())
        
        # Hash the password
        hashed_password = hash_password(password)
        
        with mysql.connector.connect(**DB_CONFIG) as connection:
            with connection.cursor(dictionary=True) as cursor:
                # Check if username already exists
                cursor.execute("SELECT username FROM users WHERE username = %s", (username,))
                if cursor.fetchone():
                    return jsonify({
                        'error': 'Username already exists'
                    }), 409
                
                # Insert new user
                insert_query = """
                    INSERT INTO users 
                    (firstname, lastname, username, password, user_key, db_type)
                    VALUES (%s, %s, %s, %s, %s, %s)
                """
                cursor.execute(insert_query, 
                             (firstname, lastname, username, hashed_password, user_key, db_type.lower()))
                connection.commit()
                
                return jsonify({
                    "user_key": user_key
                }), 201

    except Error as e:
        return jsonify({
            'error': 'Database error',
            'message': str(e)
        }), 500
    except Exception as e:
        return jsonify({
            'error': 'Server error',
            'message': str(e)
        }), 500

@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['username', 'password']
        for field in required_fields:
            if field not in data:
                return jsonify({
                    'error': f'Missing required field: {field}'
                }), 400

        # Extract data
        username = data['username']
        password = data['password']
        
        # Hash the password
        hashed_password = hash_password(password)
        
        with mysql.connector.connect(**DB_CONFIG) as connection:
            with connection.cursor(dictionary=True) as cursor:
                # Check username and password, also return db_type
                cursor.execute("""
                    SELECT user_key, db_type 
                    FROM users 
                    WHERE username = %s AND password = %s
                """, (username, hashed_password))
                
                user = cursor.fetchone()
                
                if user:
                    return jsonify({
                        'status': 'success',
                        'user_key': user['user_key'],
                        'db_type': user['db_type']
                    }), 200
                else:
                    return jsonify({
                        'status': 'failed',
                        'user_key': '-1'
                    }), 401

    except Error as e:
        return jsonify({
            'error': 'Database error',
            'message': str(e)
        }), 500
    except Exception as e:
        return jsonify({
            'error': 'Server error',
            'message': str(e)
        }), 500

if __name__ == '__main__':
    # Initialize database
    init_db()
    
    # Run the Flask app
    app.run(debug=True, port=5000)
