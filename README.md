# SCADA Monitor Project

## Description
SCADA Monitor is a real-time monitoring system for industrial networks, specialized in detecting and analyzing Modbus traffic. The project provides packet capture, analysis, and reporting capabilities for SCADA systems.

## Key Features
- Real-time network traffic monitoring
- Specific support for Modbus TCP protocol (Port 502)
- Automatic packet capture every 30 seconds
- Detailed report generation in JSON format
- Web interface for event visualization
- Automatic capture saving in PCAP format

## System Requirements
- Python 3.7+
- Flask
- Flask-SocketIO
- Scapy
- PyModbus

## Installation
1. Clone the repository:
```bash
git clone https://github.com/yourusername/SCADA_Monitor_Project.git
cd SCADA_Monitor_Project
```
