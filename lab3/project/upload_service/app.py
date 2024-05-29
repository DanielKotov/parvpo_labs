from flask import Flask, request, jsonify
import pika

app = Flask(__name__)


@app.route('/upload', methods=['POST'])
def upload():
    enc_file = request.files['file']
    if not enc_file:
        return jsonify({'message': 'No file provided'}), 400

    # Connect to RabbitMQ
    connection = pika.BlockingConnection(pika.ConnectionParameters('rabbitmq'))
    channel = connection.channel()

    # Send file to encryption service via RabbitMQ
    channel.queue_declare(queue='encrypt_queue')
    channel.basic_publish(exchange='', routing_key='encrypt_queue', body=enc_file.read())

    connection.close()

    return jsonify({'message': 'File uploaded and sent for encryption'}), 200


if __name__ == '__main__':
    app.run(debug=True)
