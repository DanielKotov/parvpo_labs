import pika
import json
from utils import encrypt_file, saves_to_db
import logging
from logging.handlers import RotatingFileHandler
from pythonjsonlogger import jsonlogger
from os import urandom
from flask import Flask


file_management = Flask(__name__)
file_management.config["SECRET_KEY"] = urandom(24)

handler = RotatingFileHandler("/dummy/file_management.log", maxBytes=2000, backupCount=10)
handler.setLevel(logging.DEBUG)

formatter = jsonlogger.JsonFormatter('%(asctime)s %(levelname)s %(name)s %(message)s')
handler.setFormatter(formatter)

logger = logging.getLogger('werkzeug')
logger.setLevel(logging.DEBUG)
logger.addHandler(handler)


@file_management.route('/')
def index():
    file_management.logger.info('file management service is running')
    return 'File management service is running'


def callback(ch, method, properties, body):
    data = json.loads(body)
    username = data['username']
    filename = data['filename']
    file_content = bytes.fromhex(data['content'])
    enc_content, iv = encrypt_file(file_content)
    try:
        saves_to_db(username, filename, enc_content, iv)
        ch.basic_ack(delivery_tag=method.delivery_tag)
    except Exception as e:
        file_management.logger.error("Failed to save files in the database:  %s", e)


def start_consumer():
    try:
        connection = pika.BlockingConnection(pika.ConnectionParameters('rabbitmq'))
        channel = connection.channel()
        channel.queue_declare(queue='file_queue', durable=True)
        channel.basic_consume(queue='file_queue', on_message_callback=callback)
        file_management.logger.info("Consumer started and waiting for messages")
        channel.start_consuming()
    except Exception as e:
        file_management.logger.error(f"Failed to start consuming or connect to RabbitMQ: %s", e)


if __name__ == "__main__":
    file_management.run(debug=True, port=5002)
