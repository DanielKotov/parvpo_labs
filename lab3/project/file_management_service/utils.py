from Crypto.Util.Cipher import AES
from Crypto.Util.padding import pad
import psycopg2
from os import urandom, getenv
import base64

BLOCK_SIZE = 32
ENCRYPTION_KEY = base64.b64decode(getenv('ENCRYPTION_KEY'))


def encrypt_file(file_content):
    iv = urandom(BLOCK_SIZE)
    cipher = AES.new(ENCRYPTION_KEY, AES.MODE_CFB, iv)
    enc_content = cipher.encrypt(pad(file_content, BLOCK_SIZE))
    return enc_content.hex(), iv.hex()


def saves_to_db(username, filename, enc_content, iv):
    connection = psycopg2.connect(
            dbname='files',
            user='postgres',
            password='postgres',
            host='postgres'
    )
    cursor = connection.cursor()
    cursor.execute(
        "INSERT INTO files (username, filename, content, iv) VALUES (%s, %s, %s, %s)",
        (username, filename, enc_content, iv)
    )
    connection.commit()
    cursor.close()
    connection.close()
