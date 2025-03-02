# Update imports and paths
from flask import Flask, render_template, jsonify, send_file
from flask_socketio import SocketIO
from datetime import datetime
import threading
import time
import random
from scapy.all import sniff, wrpcap
import os
import json
from .utils.pcap_manager import PcapManager  # Fixed relative import

app = Flask(__name__, 
    template_folder=os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates'),
    static_folder=os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static')
)
socketio = SocketIO(app, async_mode='threading', cors_allowed_origins="*")

# Update directory structure
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CAPTURE_DIR = os.path.join(BASE_DIR, "data", "pcaps")
REPORTS_DIR = os.path.join(BASE_DIR, "data", "reports")

# Add these global variables
scanning_active = True
simulation_active = True
events = []
stats = {
    "total_events": 0,
    "high_severity": 0,
    "unique_sources": set()
}

# Keep only one index route
@app.route('/')
def index():
    return render_template('index.html')
@app.route('/api/stats')
def get_stats():
    return jsonify({
        "total_events": stats["total_events"],
        "high_severity": stats["high_severity"],
        "unique_sources": len(stats["unique_sources"])
    })
# Add packet capture function
def capture_packets():
    global current_pcap
    while True:
        if scanning_active:
            try:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                current_pcap = os.path.join(CAPTURE_DIR, f"capture_{timestamp}.pcap")
                packets = sniff(prn=packet_callback, store=1, count=50, timeout=30)
                if packets:
                    wrpcap(current_pcap, packets)
                    print(f"PCAP saved: {current_pcap}")
                    generate_report(timestamp)
            except Exception as e:
                print(f"Capture error: {e}")
        time.sleep(1)
def packet_callback(packet):
    if hasattr(packet, 'src'):
        event = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "source_ip": packet.src,
            "target_ip": packet.dst if hasattr(packet, 'dst') else 'Unknown',
            "protocol": packet.type if hasattr(packet, 'type') else 'Unknown',
            "severity": random.choice(["Low", "Medium", "High"]),
            "packet_info": packet.summary()
        }
        
        events.append(event)
        stats["total_events"] += 1
        stats["unique_sources"].add(event["source_ip"])
        if event["severity"] == "High":
            stats["high_severity"] += 1
            
        socketio.emit('new_event', event)
        print(f"Emitted event: {event}")

# Remove duplicate functions and keep only one version of each:
def simulate_events():
    while True:
        if simulation_active:
            try:
                event = {
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "source_ip": f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}",
                    "target_ip": f"10.0.{random.randint(1, 254)}.{random.randint(1, 254)}",
                    "protocol": random.choice(["TCP", "UDP", "ICMP"]),
                    "severity": random.choice(["Low", "Medium", "High"]),
                    "packet_info": "Simulated packet"
                }
                
                events.append(event)
                stats["total_events"] += 1
                stats["unique_sources"].add(event["source_ip"])
                if event["severity"] == "High":
                    stats["high_severity"] += 1
                
                socketio.emit('new_event', event)
                print(f"Emitted event: {event}")
            except Exception as e:
                print(f"Event simulation error: {e}")
            time.sleep(1)

def capture_packets():
    while True:
        if scanning_active:
            try:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                pcap_file = os.path.join(CAPTURE_DIR, f"capture_{timestamp}.pcap")
                
                # Capture some packets
                packets = sniff(count=10, timeout=2)
                if packets:
                    wrpcap(pcap_file, packets)
                    print(f"PCAP saved: {pcap_file}")
                    generate_report(timestamp)
                
            except Exception as e:
                print(f"Capture error: {e}")
            time.sleep(30)

def start_threads():
    for directory in [CAPTURE_DIR, REPORTS_DIR]:
        if not os.path.exists(directory):
            os.makedirs(directory)
            print(f"Created directory: {directory}")
    
    simulation_thread = threading.Thread(target=simulate_events)
    capture_thread = threading.Thread(target=capture_packets)
    
    simulation_thread.daemon = True
    capture_thread.daemon = True
    
    simulation_thread.start()
    capture_thread.start()
    
    return [simulation_thread, capture_thread]

# Update toggle endpoint
@app.route('/api/control/toggle', methods=['POST'])
def toggle_scanning():
    global scanning_active, simulation_active
    try:
        scanning_active = not scanning_active
        simulation_active = not simulation_active
        status = "running" if scanning_active else "stopped"
        
        if not scanning_active:
            # Generate final report when stopping
            generate_report(datetime.now().strftime("%Y%m%d_%H%M%S"))
        
        socketio.emit('scanning_status', {
            "scanning": scanning_active,
            "status": status
        })
        
        return jsonify({
            "scanning": scanning_active,
            "status": status
        })
    except Exception as e:
        print(f"Toggle error: {e}")
        return jsonify({"error": str(e)}), 500
@app.route('/api/files')
def list_files():
    try:
        pcap_files = [f for f in os.listdir(CAPTURE_DIR) if f.endswith('.pcap')]
        report_files = [f for f in os.listdir(REPORTS_DIR) if f.endswith('.json')]
        return jsonify({
            "pcap_files": sorted(pcap_files, reverse=True),
            "report_files": sorted(report_files, reverse=True)
        })
    except Exception as e:
        print(f"Error listing files: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/download/<path:filename>')
def download_file(filename):
    try:
        if filename.endswith('.pcap'):
            file_path = os.path.join(CAPTURE_DIR, filename)
        elif filename.endswith('.json'):
            file_path = os.path.join(REPORTS_DIR, filename)
        else:
            return jsonify({"error": "Invalid file type"}), 400

        if os.path.exists(file_path):
            return send_file(file_path, as_attachment=True)
        return jsonify({"error": "File not found"}), 404
    except Exception as e:
        print(f"Download error: {e}")
        return jsonify({"error": str(e)}), 500
@app.route('/api/events')
def get_events():
    return jsonify(events)

# Add these variables
current_pcap = None
pcap_manager = PcapManager()

def simulate_events():
    while True:
        if simulation_active:
            try:
                event = {
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "source_ip": f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}",
                    "target_ip": f"10.0.{random.randint(1, 254)}.{random.randint(1, 254)}",
                    "protocol": random.choice(["TCP", "UDP", "ICMP"]),
                    "severity": random.choice(["Low", "Medium", "High"]),
                    "packet_info": "Simulated packet"
                }
                
                events.append(event)
                stats["total_events"] += 1
                stats["unique_sources"].add(event["source_ip"])
                if event["severity"] == "High":
                    stats["high_severity"] += 1
                
                socketio.emit('new_event', event)
                print(f"Event emitted: {event}")
            except Exception as e:
                print(f"Event simulation error: {e}")
            time.sleep(0.5)  # Faster events for testing

def capture_packets():
    while True:
        if scanning_active:
            try:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                pcap_file = os.path.join(CAPTURE_DIR, f"capture_{timestamp}.pcap")
                report_file = os.path.join(REPORTS_DIR, f"report_{timestamp}.json")
                
                # Save PCAP
                wrpcap(pcap_file, [])  # Create empty PCAP for testing
                print(f"PCAP saved: {pcap_file}")
                
                # Generate report
                with open(report_file, 'w') as f:
                    json.dump({
                        "timestamp": timestamp,
                        "stats": stats,
                        "recent_events": events[-100:]
                    }, f, default=str, indent=4)
                print(f"Report saved: {report_file}")
                
            except Exception as e:
                print(f"Capture error: {e}")
            time.sleep(30)  # Generate files every 30 seconds

def start_threads():
    for directory in [CAPTURE_DIR, REPORTS_DIR]:
        if not os.path.exists(directory):
            os.makedirs(directory)
            print(f"Created directory: {directory}")
    
    simulation_thread = threading.Thread(target=simulate_events)
    capture_thread = threading.Thread(target=capture_packets)
    
    simulation_thread.daemon = True
    capture_thread.daemon = True
    
    simulation_thread.start()
    capture_thread.start()
    
    return [simulation_thread, capture_thread]
# Add this after socketio initialization
@socketio.on('connect')
def handle_connect():
    print("Client connected")
    socketio.emit('scanning_status', {
        "scanning": scanning_active,
        "status": "running" if scanning_active else "stopped"
    })

@socketio.on('client_ready')
def handle_client_ready():
    print("Client ready")