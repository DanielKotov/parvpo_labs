from flask import Flask, request, render_template, redirect, url_for, session
from utils import *
import json
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == "POST":
        data = request.form
        username = data.get('username')
        password = data.get('password')

        if not username or not password:
            error = "Missing username or password"
            return render_template('register.html', error=error)
        if username in users.keys():
            error = "User already exists"
            return render_template('register.html', error=error)

        hash_passwd, salt = hashing(password, HASH_SALT)
        save_user_to_db(username, password, salt)
        message = "User registered successfully"
        return render_template('register.html', message=message)
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == "POST":
        username = request.form['username']
        password = request.form['password']
        if not username or not password:
            return render_template('login.html', error='Missing username of password')
        user = get_user_from_db(username)
        if user:
            db_username, db_password_hash, db_salt = user
            if hashing(password, HASH, db_salt) == db_password_hash:
                return redirect(url_for("welcome"))
            else:
                return render_template('login.html', error='Ivalid credentials')
        else:
            return render_template('login.html', error='User does not exist')
    return render_template('login.html')


@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if 'username' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        if 'file' not in request.files:
            return redirect('No file part')
        user_file = request.files['file']

        if user_file.filename == '':
            return redirect('No selected file')

        if user_file and allowed_file(user_file.filename):
            # Читаем файл и отправляем его в очередь RabbitMQ
            connection = pika.BlockingConnection(pika.ConnectionParameters('rabbitmq'))
            channel = connection.channel()
            channel.queue_declare(queue='file_queue')
            message = json.dumps({'username': session['username'], 'filename': user_file.filename, 'content': file_content.decode('latin1')})
            channel.basic_publish(exchange='', routing_key='file_queue', body=message)
            connection.close()
            return render_template('upload.html', message='File uploaded successfully')
        else:
            return render_template('upload.html', error='No file selected')
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
