import scapy.all as scapy
import pandas as pd
import joblib
import json
import time
from datetime import datetime

# Load the trained model and encoders
print("Loading model and encoders...")
clf = joblib.load('rf_model.pkl')
protocol_encoder = joblib.load('protocol_encoder.pkl')
service_encoder = joblib.load('service_encoder.pkl')
flag_encoder = joblib.load('flag_encoder.pkl')
class_encoder = joblib.load('class_encoder.pkl')

# Define a mapping for common ports to services (simplified)
# NSL-KDD services: http, smtp, ftp, ftp_data, etc.
port_to_service = {
    80: 'http',
    443: 'http', # mapping https to http for simplicity as 'https' might not be in the training set or treated as http
    21: 'ftp',
    20: 'ftp_data',
    25: 'smtp',
    22: 'ssh',
    53: 'domain',
    23: 'telnet'
}

def get_service(packet):
    if packet.haslayer(scapy.TCP):
        port = packet[scapy.TCP].dport
    elif packet.haslayer(scapy.UDP):
        port = packet[scapy.UDP].dport
    else:
        return 'other'
    
    return port_to_service.get(port, 'private') # 'private' is a common catch-all in KDD

def get_flag(packet):
    # Mapping TCP flags to KDD flag format is complex.
    # Simplified mapping:
    # SF = Normal establishment and termination
    # S0 = Connection attempt seen, no reply
    # REJ = Connection rejected
    # For a single packet, we can just guess based on the flag set.
    if packet.haslayer(scapy.TCP):
        flags = packet[scapy.TCP].flags
        if flags.S: return 'S0' # Syn only
        if flags.R: return 'REJ' # Reset
        if flags.F: return 'SF' # Fin (Termination)
        if flags.A: return 'SF' # Ack (Normal traffic)
    return 'SF' # Default to normal

def process_packet(packet):
    try:
        # Check if IP layer is present
        if not packet.haslayer(scapy.IP):
            return

        # feature extraction
        # Duration: 0 for single packet capture (real flow tracking is hard)
        duration = 0 
        
        # Protocol
        proto = packet[scapy.IP].proto
        if proto == 6:
            protocol_type = 'tcp'
        elif proto == 17:
            protocol_type = 'udp'
        elif proto == 1:
            protocol_type = 'icmp'
        else:
            return # Skip other protocols for now
            
        service = get_service(packet)
        flag = get_flag(packet)
        src_bytes = len(packet[scapy.IP].payload)
        dst_bytes = 0 # Can't know this from a single packet easily

        # Create DataFrame
        features = pd.DataFrame([{
            'duration': duration,
            'protocol_type': protocol_type,
            'service': service,
            'flag': flag,
            'src_bytes': src_bytes,
            'dst_bytes': dst_bytes
        }])

        # Encode features
        # Handle unseen values by assigning a default (like the first class)
        # This is "student logic" - not robust production logic
        
        # Protocol
        try:
            features['protocol_type'] = protocol_encoder.transform(features['protocol_type'])
        except:
             features['protocol_type'] = 0

        # Service
        try:
            features['service'] = service_encoder.transform(features['service'])
        except:
            features['service'] = service_encoder.transform(['other'])[0]

        # Flag
        try:
            features['flag'] = flag_encoder.transform(features['flag'])
        except:
            features['flag'] = flag_encoder.transform(['SF'])[0]

        # Predict
        prediction = clf.predict(features)
        label = class_encoder.inverse_transform(prediction)[0]

        # Log if anomaly
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # We define "normal" as the normal class. Everything else is an attack.
        # In KDD, 'normal' is the label.
        status = "Safe" if label == 'normal' else "Malicious"
        
        alert = {
            "timestamp": timestamp,
            "src_ip": packet[scapy.IP].src,
            "dst_ip": packet[scapy.IP].dst,
            "protocol": protocol_type,
            "prediction": label,
            "status": status
        }
        
        print(f"[{timestamp}] {status}: {label} - {alert['src_ip']} -> {alert['dst_ip']}")
        
        # Write to JSON file (append mode logic)
        with open("alerts.json", "a") as f:
            json.dump(alert, f)
            f.write("\n")

    except Exception as e:
        # print(f"Error processing packet: {e}")
        pass

print("Starting packet sniffer... (Press Ctrl+C to stop)")
# Store one initial record to create the file
with open("alerts.json", "w") as f:
    pass

# Sniff packets
# iface=None listens on all interfaces (or default)
# prn=process_packet calls the function for every packet
scapy.sniff(prn=process_packet, store=0)
