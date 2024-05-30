from os import urandom
from hashlib import sha256
import psycopg2

ALLOWED_EXTENSIONS = ['txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif']

HASH_SALT = 1
HASH = 2


def allowed_file(filename):
    return '.' in filename and \
            filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def hashing(password, mode, salt=None):
    h = sha256()
    if salt is None:
        salt = urandom(16)
    else:
        if isinstance(salt, str):
            salt = bytes.fromhex(salt)
    h.update(salt + password.encode())
    if mode == HASH_SALT:
        return h.hexdigest(), salt.hex()
    if mode == HASH:
        return h.hexdigest()


def save_user_to_db(username, password_hash, salt):
    connection = psycopg2.connect(
            dbname='users',
            user='postgres',
            password='postgres',
            host='postgres'
    )
    cursor = connection.cursor()
	cursor.execute(
			"INSERT INTO users (username, password_hash, salt) VALUES (%s, %s, %s)",
			(username, password_hash, salt)
			)
	connection.commit()
	cursor.close()
	connection.close()


def get_user_from_db(username):
	connection = psycopg2.connect(
			dbname='users',
			user='postgres',
			password='postgres',
			host='postgres'
			)
	cursor = connection.cursor()
	cursor.execute(
			"SELECT username, password_hash, salt FROM users WHERE username = %s",
			(username,)
			)
	user = cursor.fetchone()
	cursor.close()
	connection.close()
	return user
