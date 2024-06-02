from flask import Flask, request, render_template, redirect, url_for, session, jsonify
from utils import *
import pika
import json
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == "POST":
        if request.is_json:
            data = request.get_json()
        else:
            data = request.form
        username = data.get('username')
        password = data.get('password')
        if not username or not password:
            return jsonify({"error": "Missing username or password"}), 400
        if get_user_from_db(username):
            return jsonify({"error": "User already exists"}), 400
        hash_passwd, salt = hashing(password, HASH_SALT)
        save_user_to_db(username, hash_passwd, salt)
        return jsonify({"message": "User registered successfully"}), 201
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == "POST":
        if request.is_json:
            data = request.get_json()
        else:
            data = request.form

        username = data.get('username')
        password = data.get('password')
        if not username or not password:
            return jsonify({"error": 'Missing username of password'}), 400

        user = get_user_from_db(username)
        if user:
            db_username, db_password_hash, db_salt = user
            if hashing(password, HASH, db_salt) == db_password_hash:
                session['username'] = username
                return redirect(url_for("upload"))
            else:
                return jsonify({"error" : 'Ivalid credentials'}), 401
        else:
            return jsonify({'error': 'User does not exist'}), 404
    return render_template('login.html')


@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if 'username' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        if 'file' not in request.files:
            return jsonify({"error": 'No file part'}), 400
        user_file = request.files['file']

        if user_file.filename == '':
            return jsonify({"error": 'No selected file'}), 400

        if user_file and allowed_file(user_file.filename):
            # Читаем файл и отправляем его в очередь RabbitMQ
            file_content = user_file.read()
            connection = pika.BlockingConnection(pika.ConnectionParameters('rabbitmq'))
            channel = connection.channel()
            channel.queue_declare(queue='file_queue', durable=True)

            message = json.dumps({
                'username': session['username'],
                'filename': user_file.filename,
                'content': file_content.hex()
            })

            channel.basic_publish(exchange='', routing_key='file_queue', body=message)
            connection.close()
            return jsonify({'message': 'File uploaded successfully'}), 200
        else:
            return jsonify({'error': 'No file selected'}), 400
    return render_template('upload.html')


@app.route("/logout")
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))


@app.route("/welcome")
def welcome():
    return "Welcome to the system"


if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000)
