from flask import Flask, request, jsonify
import jwt
import datetime
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'

users = {}

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'message': 'Missing username or password'}), 400

    if username in users:
        return jsonify({'message': 'User already exists'}), 400

    hashed_password = generate_password_hash(password, method='sha256', salt_length=16)
    users[username] = hashed_password

    return jsonify({'message': 'User registered successfully'}), 201


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'message': 'Missing username or password'}), 400

    user = users.get(username)

    if not user or not check_password_hash(user, password):
        return jsonify({'message': 'Invalid credentials'}), 401

    token = jwt.encode({'username': username, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])
    return jsonify({'token': token}), 200


if __name__ == '__main__':
    app.run(debug=True)
