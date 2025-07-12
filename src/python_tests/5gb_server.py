from flask import Flask, Response

app = Flask(__name__)

@app.route('/')
def big_response():
    CHUNK_SIZE = 8192  # 8 KB
    TOTAL_SIZE = 5 * 1024 * 1024 * 1024  # 5 GB
    NUM_CHUNKS = TOTAL_SIZE // CHUNK_SIZE

    def generate():
        chunk = b'x' * CHUNK_SIZE
        for _ in range(NUM_CHUNKS):
            yield chunk

    return Response(generate(), content_type='application/octet-stream')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000)

