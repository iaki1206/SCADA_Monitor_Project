try:
    import flask
    print("Flask installed successfully")
except ImportError:
    print("Flask not installed")

try:
    import flask_socketio
    print("Flask-SocketIO installed successfully")
except ImportError:
    print("Flask-SocketIO not installed")

try:
    import pandas
    print("Pandas installed successfully")
except ImportError:
    print("Pandas not installed")

try:
    import numpy
    print("NumPy installed successfully")
except ImportError:
    print("NumPy not installed")

try:
    import eventlet
    print("Eventlet installed successfully")
except ImportError:
    print("Eventlet not installed")

try:
    import scapy.all
    print("Scapy installed successfully")
except ImportError:
    print("Scapy not installed")

try:
    import pymodbus
    print("PyModbus installed successfully")
except ImportError:
    print("PyModbus not installed")