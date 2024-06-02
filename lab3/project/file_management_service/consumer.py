from flask import Flask, request
import pika
import json
from app import *
import time

time.sleep(10)

def callback(ch, method, properties, body):
    data = json.loads(body)
    username = data['username']
    filename = data['filename']
    file_content = bytes.fromhex(data['content'])
    enc_content, iv = encrypt_file(file_content)
    saves_to_db(username, filename, enc_content, iv)
    ch.basic_ack(delivery_tag=method.delivery_tag)


connection = pika.BlockingConnection(pika.ConnectionParameters('rabbitmq'))
channel = connection.channel()
channel.queue_declare(queue='file_queue', durable=True)
channel.basic_consume(queue='file_queue', on_message_callback=callback)
print("Waiting for messages. To exit press CTRL+C")
channel.start_consuming()
