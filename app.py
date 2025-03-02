from flask import Flask, render_template, jsonify, send_file
from flask_socketio import SocketIO
from datetime import datetime
import threading
import time
import random
from scapy.all import sniff, wrpcap
import os
import json
from pcap_manager import PcapManager

app = Flask(__name__)
socketio = SocketIO(app, async_mode='threading', cors_allowed_origins="*")

# Add scanning control flags
scanning_active = True
simulation_active = True

# Update directory structure
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CAPTURE_DIR = os.path.join(BASE_DIR, "captures")
REPORTS_DIR = os.path.join(BASE_DIR, "reports")

# Create necessary directories
for directory in [CAPTURE_DIR, REPORTS_DIR]:
    if not os.path.exists(directory):
        try:
            os.makedirs(directory)
            print(f"Created directory: {directory}")
        except Exception as e:
            print(f"Error creating directory {directory}: {e}")

# Storage for events and packet captures
events = []
stats = {
    "total_events": 0,
    "high_severity": 0,
    "unique_sources": set()
}
current_pcap = None
# Add cleanup function
def cleanup_old_files():
    try:
        for directory in [CAPTURE_DIR, REPORTS_DIR]:
            for file in os.listdir(directory):
                file_path = os.path.join(directory, file)
                try:
                    os.remove(file_path)
                    print(f"Cleaned up: {file_path}")
                except Exception as e:
                    print(f"Error removing {file_path}: {e}")
    except Exception as e:
        print(f"Error during cleanup: {e}")

def reset_stats():
    global events, stats, current_pcap
    events.clear()
    stats["total_events"] = 0
    stats["high_severity"] = 0
    stats["unique_sources"] = set()
    current_pcap = None
    cleanup_old_files()
    print("Stats and events reset to initial state")
def packet_callback(packet):
    if packet.haslayer('IP'):
        event = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "source_ip": packet['IP'].src,
            "target_ip": packet['IP'].dst,
            "protocol": packet['IP'].proto,
            "severity": random.choice(["Low", "Medium", "High"]),
            "packet_info": packet.summary()
        }
        
        events.append(event)
        stats["total_events"] += 1
        stats["unique_sources"].add(event["source_ip"])
        if event["severity"] == "High":
            stats["high_severity"] += 1
            
        socketio.emit('new_event', event)

# Remove the duplicate route and keep only one toggle_scanning function
@app.route('/api/control/toggle', methods=['POST'])
def toggle_scanning():
    global scanning_active, simulation_active
    try:
        scanning_active = not scanning_active
        simulation_active = not simulation_active
        status = "running" if scanning_active else "stopped"
        
        if not scanning_active:
            # Generate report when stopping
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            report_file = os.path.join(REPORTS_DIR, f"report_{timestamp}.json")
            generate_report(report_file)
        
        socketio.emit('scanning_status', {
            "scanning": scanning_active,
            "status": status
        })
        
        return jsonify({
            "scanning": scanning_active,
            "status": status
        })
    except Exception as e:
        print(f"Error toggling scan: {e}")
        return jsonify({"error": str(e)}), 500

def generate_report(report_file):
    try:
        # Convert set to list for JSON serialization
        unique_sources_list = list(stats["unique_sources"])
        
        report = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "summary": {
                "total_events": stats["total_events"],
                "high_severity": stats["high_severity"],
                "unique_sources": len(unique_sources_list),
                "unique_sources_list": unique_sources_list
            },
            "events": events[-100:],  # Last 100 events
            "current_pcap": current_pcap
        }
        
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=4, default=str)
        
        print(f"Report generated: {report_file}")
        return True
    except Exception as e:
        print(f"Error generating report: {e}")
        return False

def capture_packets():
    global current_pcap
    while True:
        if scanning_active:
            try:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                current_pcap = os.path.join(CAPTURE_DIR, f"capture_{timestamp}.pcap")
                packets = sniff(prn=packet_callback, store=1, count=50, timeout=30)  # 30-second captures
                if packets:
                    wrpcap(current_pcap, packets)
                    print(f"Packet capture saved: {current_pcap}")
            except Exception as e:
                print(f"Error in packet capture: {e}")
        time.sleep(1)

def simulate_events():
    while True:
        if simulation_active:
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
            print(f"Event emitted: {event}")  # Debug output
        time.sleep(random.uniform(1, 3))  # Random delay between 1-3 seconds

@app.route('/api/report')
def get_report():
    try:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = os.path.join(REPORTS_DIR, f"report_{timestamp}.json")
        
        # Convert set to list for JSON serialization
        unique_sources_list = list(stats["unique_sources"])
        
        report = {
            "summary": {
                "total_events": stats["total_events"],
                "high_severity": stats["high_severity"],
                "unique_sources": len(unique_sources_list),
                "unique_sources_list": unique_sources_list
            },
            "events": events,
            "current_pcap": current_pcap
        }
        
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=4, default=str)
        
        print(f"Report saved to: {report_file}")
        return send_file(
            report_file,
            as_attachment=True,
            download_name=f"report_{timestamp}.json",
            mimetype='application/json'
        )
    except Exception as e:
        print(f"Error generating report: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/pcap/current')
def get_current_pcap():
    global current_pcap
    print(f"Requested PCAP file: {current_pcap}")
    if current_pcap and os.path.exists(current_pcap):
        try:
            return send_file(
                current_pcap,
                as_attachment=True,
                download_name=f"capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
            )
        except Exception as e:
            print(f"Error sending PCAP file: {e}")
            return jsonify({"error": str(e)}), 500
    return jsonify({"error": "No capture file available"}), 404

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

@app.route('/api/events')
def get_events():
    return jsonify(events)

def reset_stats():
    global events, stats
    events.clear()
    stats["total_events"] = 0
    stats["high_severity"] = 0
    stats["unique_sources"] = set()
    print("Stats and events reset to initial state")
def start_threads():
    # Reset stats before starting threads
    reset_stats()
    
    simulation_thread = threading.Thread(target=simulate_events)
    capture_thread = threading.Thread(target=capture_packets)
    
    simulation_thread.daemon = True
    capture_thread.daemon = True
    
    simulation_thread.start()
    capture_thread.start()
    
    return simulation_thread, capture_thread

# Export the threads
threads = None
if __name__ != '__main__':
    threads = start_threads()
if __name__ == '__main__':
    threads = start_threads()
    socketio.run(app, debug=False, allow_unsafe_werkzeug=True)
# Remove the last line that runs the app
# socketio.run(app, debug=True)
# Add new route for custom downloads
@app.route('/api/download/<path:filename>')
def download_file(filename):
    try:
        # Determine file type and directory
        if filename.endswith('.pcap'):
            file_path = os.path.join(CAPTURE_DIR, filename)
        elif filename.endswith('.json'):
            file_path = os.path.join(REPORTS_DIR, filename)
        else:
            return jsonify({"error": "Invalid file type"}), 400

        if os.path.exists(file_path):
            return send_file(
                file_path,
                as_attachment=True,
                download_name=filename,
                mimetype='application/octet-stream'
            )
        else:
            return jsonify({"error": "File not found"}), 404
    except Exception as e:
        print(f"Download error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/files')
def list_files():
    try:
        pcap_files = sorted(
            [f for f in os.listdir(CAPTURE_DIR) if f.endswith('.pcap')],
            reverse=True
        )
        report_files = sorted(
            [f for f in os.listdir(REPORTS_DIR) if f.endswith('.json')],
            reverse=True
        )
        return jsonify({
            "pcap_files": pcap_files,
            "report_files": report_files
        })
    except Exception as e:
        print(f"File listing error: {e}")
        return jsonify({"error": str(e)}), 500