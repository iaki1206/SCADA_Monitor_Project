import os
import sys
import webbrowser
from app import app, socketio, start_threads

def main():
    print("Starting SCADA Security Monitor...")
    print("Starting monitoring threads...")
    threads = start_threads()
    print("Opening web browser...")
    webbrowser.open('http://localhost:5000')
    socketio.run(app, debug=False, allow_unsafe_werkzeug=True)

if __name__ == '__main__':
    main()