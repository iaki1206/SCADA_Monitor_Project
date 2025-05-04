# SCADA Monitor Project

## Descriere
SCADA Monitor este un sistem de monitorizare în timp real pentru rețele industriale, specializat în detectarea și analiza traficului Modbus. Proiectul oferă capabilități de captură de pachete, analiză și raportare pentru sisteme SCADA.

## Caracteristici Principale
- Monitorizare trafic rețea în timp real
- Suport specific pentru protocolul Modbus TCP (Port 502)
- Captură automată de pachete la fiecare 30 secunde
- Generare detaliată de rapoarte în format JSON
- Interfață web pentru vizualizarea evenimentelor
- Salvare automată în format PCAP

## Cerințe Sistem
- Python 3.7+
- Flask
- Flask-SocketIO
- Scapy
- PyModbus

## Instalare
1. Clonează repository-ul:
```bash
git clone https://github.com/username/SCADA_Monitor_Project.git
cd SCADA_Monitor_Project
```
