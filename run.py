import webbrowser
import os
from src.app import app, socketio, start_threads

if __name__ == '__main__':
    threads = start_threads()
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)