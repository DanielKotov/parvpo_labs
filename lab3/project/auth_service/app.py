from flask import Flask, request, jsonify, render_template, redirect, url_for
from os import urandom
from hashlib import sha256
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'

users = {}
HASH_SALT = 1
HASH = 2


def hashing(password, mode, salt=None):
    h = sha256()
    if salt is None:
        salt = urandom(16)
    h.update(salt + password)
    if mode == HASH_SALT:
        return h.hexdigest(), salt
    if mode == HASH:
        return h.hexdigest()


@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'message': 'Missing username or password'}), 400

    if username in users:
        return jsonify({'message': 'User already exists'}), 400

    users[username] = hashing(password, 1)
    return jsonify({'message': 'User registered successfully'}), 201


@app.route('/login', methods=['POST'])
def login():
    if request.method == "POST":
        username = request.form['username']
        password = request.form['password']

        if not username or not password:
            return jsonify({'message': 'Missing username or password'}), 400
        hsh, salt = users.get(username)
        if hashing(password, 2, salt) == hsh:
            return redirect(url_for("welcome"))
        else:
            return jsonify({'message': 'Invalid credentials'}), 401
    return render_template('login.html')


if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000)
