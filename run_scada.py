import os
import sys
# Add the project root directory to Python path
project_root = os.path.dirname(os.path.abspath(__file__))
sys.path.append(project_root)
from src.app import app, socketio, start_threads
import webbrowser

def main():
    print("Starting SCADA Security Monitor...")
    print("Starting monitoring threads...")
    threads = start_threads()
    print("Opening web browser...")
    webbrowser.open('http://localhost:5000')
    socketio.run(app, debug=False, allow_unsafe_werkzeug=True)

if __name__ == '__main__':
    main()