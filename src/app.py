# Update imports and paths
from flask import Flask, render_template, jsonify, send_file, request
from flask_socketio import SocketIO
from datetime import datetime
import threading
import time
import random
from scapy.all import sniff, wrpcap, TCP
import os
import json
from pymodbus.client import ModbusTcpClient
from utils.pcap_manager import PcapManager

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
current_pcap = None
pcap_manager = PcapManager()

stats = {
    "total_events": 0,
    "high_severity": 0,
    "unique_sources": set()
}

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

def packet_callback(packet):
    if hasattr(packet, 'src'):
        is_modbus = False
        modbus_info = {}
        
        if TCP in packet and (packet[TCP].sport == 502 or packet[TCP].dport == 502):
            is_modbus = True
            modbus_info = {
                "function_code": "Unknown",
                "unit_id": "Unknown",
                "data_length": len(packet[TCP].payload) if hasattr(packet[TCP], 'payload') else 0
            }
        
        event = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "source_ip": packet.src,
            "target_ip": packet.dst if hasattr(packet, 'dst') else 'Unknown',
            "protocol": "Modbus TCP" if is_modbus else (packet.type if hasattr(packet, 'type') else 'Unknown'),
            "severity": "High" if is_modbus else random.choice(["Low", "Medium", "High"]),
            "packet_info": packet.summary(),
            "modbus_details": modbus_info if is_modbus else None
        }
        
        events.append(event)
        stats["total_events"] += 1
        stats["unique_sources"].add(event["source_ip"])
        if event["severity"] == "High":
            stats["high_severity"] += 1
            
        socketio.emit('new_event', event)
        print(f"Event emitted: {event}")

def capture_packets():
    while True:
        if scanning_active:
            try:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                pcap_file = os.path.join(CAPTURE_DIR, f"capture_{timestamp}.pcap")
                report_file = os.path.join(REPORTS_DIR, f"report_{timestamp}.json")
                
                print("Starting packet capture...")
                packets = sniff(filter="port 502 or not port 502", count=100, timeout=30)
                
                if packets:
                    wrpcap(pcap_file, packets)
                    print(f"PCAP saved: {pcap_file}")
                    
                    packet_analysis = {
                        "total_packets": len(packets),
                        "protocols": {},
                        "source_ips": set(),
                        "dest_ips": set(),
                        "timestamp": timestamp,
                        "modbus_stats": {
                            "total_modbus_packets": 0,
                            "function_codes": {},
                            "unit_ids": set()
                        }
                    }
                    
                    for packet in packets:
                        if TCP in packet:
                            if packet[TCP].sport == 502 or packet[TCP].dport == 502:
                                packet_analysis["modbus_stats"]["total_modbus_packets"] += 1
                        
                        if 'IP' in packet:
                            proto = packet['IP'].proto
                            proto_name = {1: "ICMP", 6: "TCP", 17: "UDP"}.get(proto, str(proto))
                            packet_analysis["protocols"][proto_name] = packet_analysis["protocols"].get(proto_name, 0) + 1
                            
                            packet_analysis["source_ips"].add(packet['IP'].src)
                            packet_analysis["dest_ips"].add(packet['IP'].dst)
                    
                    packet_analysis["source_ips"] = list(packet_analysis["source_ips"])
                    packet_analysis["dest_ips"] = list(packet_analysis["dest_ips"])
                    packet_analysis["modbus_stats"]["unit_ids"] = list(packet_analysis["modbus_stats"]["unit_ids"])
                    
                    report_data = {
                        "capture_file": pcap_file,
                        "analysis": packet_analysis,
                        "stats": {
                            "unique_sources": len(packet_analysis["source_ips"]),
                            "unique_destinations": len(packet_analysis["dest_ips"]),
                            "protocol_distribution": packet_analysis["protocols"],
                            "modbus_packets": packet_analysis["modbus_stats"]["total_modbus_packets"]
                        }
                    }
                    
                    with open(report_file, 'w') as f:
                        json.dump(report_data, f, indent=4)
                    print(f"Analysis report saved: {report_file}")
                
            except Exception as e:
                print(f"Capture error: {e}")
            time.sleep(30)

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
            time.sleep(1)

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

@app.route('/api/control/toggle', methods=['POST'])
def toggle_scanning():
    global scanning_active, simulation_active
    try:
        scanning_active = not scanning_active
        simulation_active = not simulation_active
        status = "running" if scanning_active else "stopped"
        
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

@app.route('/api/control/shutdown', methods=['POST'])
def shutdown_server():
    global scanning_active, simulation_active
    scanning_active = False
    simulation_active = False
    
    socketio.emit('scanning_status', {
        "scanning": False,
        "status": "stopped"
    })
    
    func = request.environ.get('werkzeug.server.shutdown')
    if func is None:
        raise RuntimeError('Not running with Werkzeug server')
    func()
    return jsonify({"status": "Server shutting down..."})

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

if __name__ == '__main__':
    threads = start_threads()
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)