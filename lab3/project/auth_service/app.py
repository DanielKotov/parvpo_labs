from flask import Flask, request, jsonify, render_template, redirect, url_for
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
    if request.method == "POST":
        username = request.form['username']
        password = request.form['password']

        if not username or not password:
            return jsonify({'message': 'Missing username or password'}), 400

        if users.get(username) == password:
            return redirect(url_for("welcome"))
        else:
            return jsonify({'message': 'Invalid credentials'}), 401
    return render_template('login.html')


if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000)
