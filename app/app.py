from flask import Flask

app = Flask(__name__)

@app.route('/')
def hello():
    return "Hello from Flask in a devcontainer!"

if __name__ == '__main__':
    # It's often better to use a WSGI server in production, but for this POC, we'll use Flask's built-in server.
    app.run(host='0.0.0.0', port=5000, debug=True)
