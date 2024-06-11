from flask import Flask, request, render_template, redirect, url_for, session, jsonify, g
from utils import *
import pika
import json
import time
import logging
from logging.handlers import RotatingFileHandler
import logging.config
from pythonjsonlogger import jsonlogger

app = Flask(__name__)
handler = RotatingFileHandler('/dummy/auth_service.log', maxBytes=2000, backupCount=10)
handler.setLevel(logging.DEBUG)

formatter = jsonlogger.JsonFormatter('%(asctime)s %(levelname)s %(name)s %(message)s')
handler.setFormatter(formatter)
app.logger.addHandler(handler)

log = logging.getLogger('werkzeug')
log.setLevel(logging.DEBUG)
log.addHandler(handler)

@app.route("/")
def main():
    app.logger.debug("Debug log level")
    app.logger.info("Program running correctly")
    app.logger.warning("Warning: low disk space")
    app.logger.error("Error!")
    app.logger.critical("Program halt!")
    return "logger levels"


@app.before_request
def start_timer():
    g.start = time.time()


@app.route('/hello', methods=['GET', 'POST'])
def hello():
    app.logger.info("Hello from app.py")
    return "Hello"


def register():
    if request.method == "POST":
        if request.is_json:
            data = request.get_json()
        else:
            data = request.form
        username = data.get('username')
        password = data.get('password')
        if not username or not password:
            app.logger.warning("Missing username of password during registration")
            return jsonify({"error": "Missing username or password"}), 400
        if get_user_from_db(username):
            app.logger.warning("Attempt to register with existing username: {username}")
            return jsonify({"error": "User already exists"}), 400
        hash_passwd, salt = hashing(password, HASH_SALT)
        save_user_to_db(username, hash_passwd, salt)
        app.logger.info(f"User registered successfully: {username}")
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
            app.logger.warning("Missing username or password during loging")
            return jsonify({"error": 'Missing username of password'}), 400

        user = get_user_from_db(username)
        if user:
            db_username, db_password_hash, db_salt = user
            if hashing(password, HASH, db_salt) == db_password_hash:
                session['username'] = username
                app.logger.info(f"User logged succesfully: {username}")
                return redirect(url_for("upload"))
            else:
                app.logger.warning("Attempt to register with existing username: {username}")
                return jsonify({"error" : 'Ivalid credentials'}), 401
        else:
            app.logger.warning(f"User already exists: {username}")
            return jsonify({'error': 'User does not exist'}), 404
    return render_template('login.html')


@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if 'username' not in session:
        app.logger.warning("Unathorized attempt to /upload")
        return redirect(url_for('login'))

    if request.method == 'POST':
        if 'file' not in request.files:
            app.logger.warning("No file part in upload request")
            return jsonify({"error": 'No file part'}), 400
        user_file = request.files['file']

        if user_file.filename == '':
            app.logger.warning("No file part in upload request")
            return jsonify({"error": 'No selected file'}), 400

        if user_file and allowed_file(user_file.filename):
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
            app.logger.info(f"File uploaded successfully: {user_file.filename} by {session['username']}")
            return jsonify({'message': 'File uploaded successfully'}), 200
        else:
            app.logger.warning(f"Invalid file upload attempt by {session['username']}")
            return jsonify({'error': 'No file selected'}), 400
    return render_template('upload.html')


@app.route("/logout")
def logout():
    session.pop('username', None)
    app.logger.info(f"User logged out: {username}")
    return redirect(url_for('login'))


@app.route("/welcome")
def welcome():
    return "Welcome to the system"


if __name__ == '__main__':
    app.run(debug=True)
