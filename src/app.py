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
from .utils.pcap_manager import PcapManager  # Use relative import

app = Flask(__name__, 
    template_folder=os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates'),
    static_folder=os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static')
)
socketio = SocketIO(app, async_mode='threading', cors_allowed_origins="*")

# Update directory structure
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CAPTURE_DIR = os.path.join(BASE_DIR, "data", "pcaps")
REPORTS_DIR = os.path.join(BASE_DIR, "data", "reports")

# Global variables
scanning_active = False  # Start with capture disabled
simulation_active = False
events = []
current_pcap = None
pcap_manager = PcapManager()

stats = {
    "total_events": 0,
    "high_severity": 0,
    "unique_sources": set()
}

def start_threads():
    # Create necessary directories
    for directory in [CAPTURE_DIR, REPORTS_DIR]:
        if not os.path.exists(directory):
            os.makedirs(directory)
            print(f"Created directory: {directory}")
    
    # Optimize threads
    simulation_thread = threading.Thread(target=simulate_events, daemon=True)
    capture_thread = threading.Thread(target=capture_packets, daemon=True)
    
    simulation_thread.start()
    capture_thread.start()
    
    return [simulation_thread, capture_thread]

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
        
        print(f"Monitoring {status}")
        return jsonify({
            "scanning": scanning_active,
            "status": status,
            "message": f"Monitoring has been {status}"
        })
    except Exception as e:
        print(f"Toggle error: {e}")
        return jsonify({"error": str(e)}), 500

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
                    
                    packet_analysis = analyze_packets(packets, timestamp)
                    generate_report(packet_analysis, pcap_file, report_file)
                
            except Exception as e:
                print(f"Capture error: {e}")
            time.sleep(30)  # Wait 30 seconds between captures

def analyze_packets(packets, timestamp):
    analysis = {
        "total_packets": len(packets),
        "protocols": {},
        "source_ips": set(),
        "dest_ips": set(),
        "timestamp": timestamp,
        "modbus_stats": {
            "total_modbus_packets": 0,
            "function_codes": {},
            "unit_ids": set()
        },
        "security_analysis": {
            "potential_threats": [],
            "recommendations": [],
            "risk_level": "Low",
            "detected_threats": []
        },
        "network_health": {
            "latency": {},
            "packet_loss": 0,
            "bandwidth_usage": "Normal"
        }
    }
    
    for packet in packets:
        analyze_single_packet(packet, analysis)
    
    generate_security_recommendations(analysis)  # This function is missing
    return analysis

def analyze_single_packet(packet, analysis):
    if TCP in packet:
        # Check for potential port scanning
        if packet[TCP].sport == 502 or packet[TCP].dport == 502:
            analysis["modbus_stats"]["total_modbus_packets"] += 1
            analyze_modbus_packet(packet, analysis)
            
            # Detect potential Modbus-specific threats
            if packet[TCP].flags == 'S':  # SYN packets
                threat = {
                    "type": "Port Scanning",
                    "severity": "High",
                    "source": packet.src,
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "details": "Potential Modbus port scanning detected",
                    "solution": "Implement firewall rules to limit Modbus access to known IP addresses",
                    "mitigation_steps": [
                        "Configure firewall to whitelist known Modbus devices",
                        "Implement rate limiting for Modbus connections",
                        "Enable logging for all Modbus connection attempts"
                    ]
                }
                analysis["security_analysis"]["detected_threats"].append(threat)
        
        # Check for potential DoS
        if len(analysis["source_ips"]) > 100:  # Too many source IPs
            threat = {
                "type": "Potential DoS Attack",
                "severity": "Critical",
                "source": "Multiple Sources",
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "details": "Unusual number of source IPs detected",
                "solution": "Implement rate limiting and DoS protection mechanisms",
                "mitigation_steps": [
                    "Deploy DoS protection at network edge",
                    "Configure SYN flood protection",
                    "Set up traffic monitoring and alerting"
                ]
            }
            analysis["security_analysis"]["detected_threats"].append(threat)
    
    if 'IP' in packet:
        analyze_ip_packet(packet, analysis)
        
        # Check for suspicious IP patterns
        if packet['IP'].src.startswith('0.') or packet['IP'].src.startswith('127.'):
            threat = {
                "type": "IP Spoofing",
                "severity": "High",
                "source": packet['IP'].src,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "details": "Potentially spoofed IP address detected",
                "solution": "Implement IP filtering and validation mechanisms",
                "mitigation_steps": [
                    "Configure ingress filtering",
                    "Implement reverse path forwarding checks",
                    "Set up IP reputation monitoring"
                ]
            }
            analysis["security_analysis"]["detected_threats"].append(threat)

def generate_report(analysis, pcap_file, report_file):
    # Ensure we keep .json extension
    if not report_file.endswith('.json'):
        report_file = report_file + '.json'
    
    report_data = {
        "report_metadata": {
            "capture_time": analysis['timestamp'],
            "pcap_file": pcap_file,
            "report_generated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "analysis_version": "1.0"
        },
        "network_statistics": {
            "total_packets": analysis['total_packets'],
            "protocol_distribution": analysis['protocols'],
            "unique_sources": list(analysis['source_ips']),
            "unique_destinations": list(analysis['dest_ips'])
        },
        "modbus_analysis": {
            "total_modbus_packets": analysis['modbus_stats']['total_modbus_packets'],
            "function_codes": analysis['modbus_stats']['function_codes'],
            "unit_ids": list(analysis['modbus_stats']['unit_ids']),
            "suspicious_operations": []
        },
        "security_analysis": {
            "risk_level": analysis['security_analysis']['risk_level'],
            "detected_threats": [
                {
                    "type": threat['type'],
                    "severity": threat['severity'],
                    "source": threat['source'],
                    "timestamp": threat['timestamp'],
                    "details": threat['details'],
                    "recommended_solution": threat['solution'],
                    "mitigation_steps": threat.get('mitigation_steps', [])
                }
                for threat in analysis['security_analysis']['detected_threats']
            ],
            "recommendations": analysis['security_analysis']['recommendations']
        },
        "network_health": {
            "latency_stats": analysis['network_health']['latency'],
            "packet_loss_rate": analysis['network_health']['packet_loss'],
            "bandwidth_status": analysis['network_health']['bandwidth_usage'],
            "performance_metrics": {
                "average_response_time": "N/A",
                "packet_error_rate": "N/A",
                "network_utilization": "N/A"
            }
        }
    }
    
    with open(report_file, 'w') as f:
        json.dump(report_data, f, indent=4)
    
    print(f"Analysis report saved: {report_file}")

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
    socketio.run(app, 
                 debug=False,  # Disable debug mode for production
                 host='127.0.0.1',  # Only listen on localhost
                 port=5000,
                 allow_unsafe_werkzeug=True)  # Required for SocketIO


def analyze_modbus_packet(packet, analysis):
    """Analyze Modbus packet details"""
    try:
        if TCP in packet and packet.haslayer('Raw'):
            # Extract Modbus function code
            data = bytes(packet['Raw'])
            if len(data) > 7:  # Minimum Modbus packet length
                function_code = data[7]
                analysis['modbus_stats']['function_codes'][function_code] = \
                    analysis['modbus_stats']['function_codes'].get(function_code, 0) + 1
                
                # Extract unit ID
                unit_id = data[6]
                analysis['modbus_stats']['unit_ids'].add(unit_id)
    except Exception as e:
        print(f"Error analyzing Modbus packet: {e}")

def analyze_ip_packet(packet, analysis):
    """Analyze IP packet details"""
    try:
        if 'IP' in packet:
            # Add source and destination IPs
            analysis['source_ips'].add(packet['IP'].src)
            analysis['dest_ips'].add(packet['IP'].dst)
            
            # Add protocol information
            proto = packet['IP'].proto
            proto_name = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}.get(proto, str(proto))
            analysis['protocols'][proto_name] = analysis['protocols'].get(proto_name, 0) + 1
            
            # Basic latency calculation for TCP packets
            if TCP in packet:
                analysis['network_health']['latency'][packet['IP'].src] = 0  # Placeholder for actual latency
    except Exception as e:
        print(f"Error analyzing IP packet: {e}")

def generate_security_recommendations(analysis):
    """Generate security recommendations based on packet analysis."""
    if analysis["modbus_stats"]["total_modbus_packets"] > 0:
        analysis["security_analysis"]["recommendations"].append(
            "Implement Modbus TCP whitelist for known devices"
        )
    
    if len(analysis["source_ips"]) > 100:
        analysis["security_analysis"]["recommendations"].append(
            "Implement rate limiting to prevent potential DoS attacks"
        )
        analysis["security_analysis"]["risk_level"] = "High"
    
    if analysis["modbus_stats"]["total_modbus_packets"] > 1000:
        analysis["security_analysis"]["recommendations"].append(
            "Monitor for potential Modbus flooding attacks"
        )

    try:
        # Evaluate risk level
        threat_count = len(analysis['security_analysis']['detected_threats'])
        if threat_count > 5:
            analysis['security_analysis']['risk_level'] = "Critical"
        elif threat_count > 2:
            analysis['security_analysis']['risk_level'] = "High"
        elif threat_count > 0:
            analysis['security_analysis']['risk_level'] = "Medium"
        
        # Generate recommendations
        recommendations = []
        
        # Check for basic security issues
        if analysis['modbus_stats']['total_modbus_packets'] > 0:
            recommendations.append({
                "priority": "High",
                "issue": "Modbus traffic detected",
                "solution": "Implement Modbus security controls and monitoring"
            })
        
        if len(analysis['source_ips']) > 50:
            recommendations.append({
                "priority": "High",
                "issue": "High number of unique source IPs",
                "solution": "Implement network segmentation and access controls"
            })
        
        analysis['security_analysis']['recommendations'] = recommendations
    except Exception as e:
        print(f"Error generating security recommendations: {e}")