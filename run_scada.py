import os
import sys
import signal
project_root = os.path.dirname(os.path.abspath(__file__))
sys.path.append(project_root)
from src.app import app, socketio, start_threads
import webbrowser

def signal_handler(sig, frame):
    print("Oprire aplicație...")
    sys.exit(0)

def main():
    signal.signal(signal.SIGINT, signal_handler)
    print("Starting SCADA Security Monitor...")
    print("Starting monitoring threads...")
    threads = start_threads()
    print("Opening web browser...")
    webbrowser.open('http://localhost:5000')
    try:
        socketio.run(app, debug=False, allow_unsafe_werkzeug=True)
    except KeyboardInterrupt:
        print("Oprire aplicație...")
    finally:
        print("Aplicație oprită cu succes.")

if __name__ == '__main__':
    main()