import os
import sys
import signal
project_root = os.path.dirname(os.path.abspath(__file__))
sys.path.append(project_root)
from src.app import app, socketio, start_threads
import webbrowser

def signal_handler(sig, frame):
    print("Stopping application...")
    sys.exit(0)

def main():
    signal.signal(signal.SIGINT, signal_handler)
    print("Starting SCADA Security Monitor...")
    print("Starting monitoring threads...")
    threads = start_threads()
    print("Opening web browser...")
    # Use localhost with port 5000
    local_url = 'http://127.0.0.1:5000'
    webbrowser.open(local_url)
    try:
        # Run the application locally
        socketio.run(app, 
                    host='127.0.0.1',
                    port=5000,
                    debug=False, 
                    allow_unsafe_werkzeug=True)
    except KeyboardInterrupt:
        print("Stopping application...")
    finally:
        print("Application stopped successfully.")

if __name__ == '__main__':
    main()