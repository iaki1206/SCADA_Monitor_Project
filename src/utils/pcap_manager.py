# Update imports and paths
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
        self.pcap_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'data', 'pcaps')
        self._ensure_directories()

    def _ensure_directories(self):
        if not os.path.exists(self.pcap_dir):
            os.makedirs(self.pcap_dir)

    def start_capture(self):
        self.is_capturing = True
        self.capture_thread = threading.Thread(target=self._capture_loop)
        self.capture_thread.daemon = True
        self.capture_thread.start()

    def stop_capture(self):
        self.is_capturing = False
        if self.capture_thread:
            self.capture_thread.join(timeout=1)
        self._save_current_pcap()

    def _capture_loop(self):
        while self.is_capturing:
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