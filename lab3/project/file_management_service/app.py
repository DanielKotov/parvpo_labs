from flask import Flask, request, jsonify
import psycopg2

app = Flask(__name__)

# Connect to PostgreSQL
conn = psycopg2.connect("dbname=files_db user=postgres password=postgres host=db")
cursor = conn.cursor()

@app.route('/files', methods=['POST'])
def add_file():
    data = request.get_json()
    filename = data.get('filename')
    size = data.get('size')
    file_type = data.get('file_type')

    if not filename or not size or not file_type:
        return jsonify({'message': 'Missing file information'}), 400

    cursor.execute("INSERT INTO files (filename, size, file_type) VALUES (%s, %s, %s)", (filename, size, file_type))
    conn.commit()

    return jsonify({'message': 'File metadata saved'}), 201

if __name__ == '__main__':
    app.run(debug=True)
