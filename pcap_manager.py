import os
from datetime import datetime
from scapy.all import wrpcap
import threading
import time

class PcapManager:
    def __init__(self):
        self.is_capturing = False
        self.capture_thread = None
        self.current_packets = []
        self.pcap_dir = 'pcaps'
        self.ensure_directories()

    def ensure_directories(self):
        if not os.path.exists(self.pcap_dir):
            os.makedirs(self.pcap_dir)

    def start_capture(self):
        self.is_capturing = True
        self.capture_thread = threading.Thread(target=self._capture_loop)
        self.capture_thread.daemon = True
        self.capture_thread.start()

    def _generate_report(self):
        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            if not os.path.exists('reports'):
                os.makedirs('reports')
                
            report_path = os.path.join('reports', f'report_{timestamp}.txt')
            
            # Generate detailed report
            with open(report_path, 'w') as f:
                f.write(f"SCADA Security Report - {datetime.now()}\n")
                f.write("================================\n\n")
                
                # Add packet statistics
                f.write("Packet Statistics:\n")
                f.write("-----------------\n")
                f.write(f"Total Packets Captured: {len(self.current_packets)}\n\n")
                
                # Add protocol breakdown
                protocols = {}
                for packet in self.current_packets:
                    proto = packet.summary()
                    protocols[proto] = protocols.get(proto, 0) + 1
                
                f.write("Protocol Breakdown:\n")
                for proto, count in protocols.items():
                    f.write(f"- {proto}: {count}\n")
                
                f.write("\nDetailed Events:\n")
                f.write("--------------\n")
                for packet in self.current_packets:
                    f.write(f"{packet.time}: {packet.summary()}\n")
                
            return report_path
        except Exception as e:
            print(f"Error generating report: {e}")
            return None
    def stop_capture(self):
        self.is_capturing = False
        if self.capture_thread:
            self.capture_thread.join()
        self._save_current_pcap()
        report_path = self._generate_report()
        self.current_packets = []  # Clear packets after report generation
        return report_path

    def _capture_loop(self):
        while self.is_capturing:
            # Save PCAP every 30 seconds
            time.sleep(30)
            self._save_current_pcap()

    def _save_current_pcap(self):
        if self.current_packets:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f'capture_{timestamp}.pcap'
            filepath = os.path.join(self.pcap_dir, filename)
            wrpcap(filepath, self.current_packets)
            self.current_packets = []

    def add_packet(self, packet):
        if self.is_capturing:
            self.current_packets.append(packet)