import pika
import json
from utils import *

def callback(ch, method, properties, body):
    data = json.loads(body)
    username = data['username']
    filename = data['filename']
    file_content = data['content']
    enc_content, iv = encrypt_file(file_content)
    save_to_db(username, filename, enc_content, iv)


connection = pika.BlockingConnection(pika.ConnectionParameters('rabbitmq'))
channel = connection.channel()
channel.queue_declare(queue='file_queue')
channel.basic_consume(queue='file_queue', on_message_callback=callback, auto_ack=True)
channel.start_consuming()
