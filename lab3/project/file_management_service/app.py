from flask import Flask, request
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import psycopg2
from os import urandom, getenv
import base64

BLOCK_SIZE = 16
ENCRYPTION_KEY = base64.b64decode(getenv('ENCRYPTION_KEY'))

app = Flask(__name__)

@app.route('/')
def index():
    return 'File management service is running'


def encrypt_file(file_content):
    iv = urandom(BLOCK_SIZE)
    cipher = AES.new(ENCRYPTION_KEY, AES.MODE_CFB, iv)
    enc_content = cipher.encrypt(pad(file_content, BLOCK_SIZE))
    return enc_content.hex(), iv.hex()


def saves_to_db(username, filename, enc_content, iv):
    con = psycopg2.connect(
            user='postgres',
            password='postgres',
            host='postgres',
            port="5432"
    )
    cur = con.cursor()
    cur.execute(
        "INSERT INTO files (username, filename, content, iv) VALUES (%s, %s, %s, %s)",
        (username, filename, enc_content, iv)
    )
    con.commit()
    cur.close()
    con.close()
