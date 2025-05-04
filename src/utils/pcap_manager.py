class PcapManager:
    def __init__(self):
        self.current_pcap = None
        self.capture_active = False
    
    def start_capture(self):
        self.capture_active = True
    
    def stop_capture(self):
        self.capture_active = False
    
    def get_current_pcap(self):
        return self.current_pcap