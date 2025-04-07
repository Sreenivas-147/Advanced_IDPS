from flask import Flask, render_template, jsonify, send_from_directory
import threading
import time
from scapy.all import sniff, IP, TCP, UDP
import joblib
import numpy as np
import smtplib
from email.message import EmailMessage
import datetime
import socket

app = Flask(__name__)

LOG_FILE = "D:/Advanced_IDPS/logs.txt"
MODEL_PATH = "D:/Advanced_IDPS/Models/idps_model.pkl"
APP_PASSWORD = "yxmtvlkwddvsyqgg"
ADMIN_EMAIL = "sreenivasulut147@gmail.com"
RECIPIENT_EMAIL = "ssreenivasulu392@gmail.com"

ATTACK_THRESHOLD = 3
COOLDOWN_PERIOD = 600
LOG_VISIBLE = True

blocked_ips = {}
alert_history = {}
attack_logs = []
false_positive_ips = {}

HOST_IP = socket.gethostbyname(socket.gethostname())
model = joblib.load(MODEL_PATH)

WHITELIST_IPS = {
    "192.168.1.1", "192.168.1.2", "192.168.1.9",
    "127.0.0.1",
    "8.8.8.",
    "142.250.", "142.251.", "172.217.",
    "199.232.", "216.58.",
    "3.7.", "3.233.",
    "52.231.", "52.187.",
    "23.65.", "23.38.",
    "4.186.",
    "20.190.", "20.24.", "20.189.", "40.104.",
    "13.107.", "204.79.",
    "104.16.", "104.18.", "104.208.",
    "172.64.", "172.65.",
    "150.171."
}

def is_safe_ip(ip):
    return any(ip.startswith(prefix) for prefix in WHITELIST_IPS)

def log_attack(ip, attack_type):
    log_entry = f"[{datetime.datetime.now()}] Attack detected from {ip} - Type: {attack_type}\n"
    attack_logs.append(log_entry)
    with open(LOG_FILE, "a") as f:
        f.write(log_entry)

def send_alert(ip, attack_type):
    key = f"{ip}_{attack_type}"
    current_time = time.time()
    if key not in alert_history or (current_time - alert_history[key]) > COOLDOWN_PERIOD:
        alert_history[key] = current_time
        msg = EmailMessage()
        msg["Subject"] = "Intrusion Alert: Attack Detected"
        msg["From"] = ADMIN_EMAIL
        msg["To"] = RECIPIENT_EMAIL
        msg.set_content(f"ALERT: An attack was detected from IP {ip} ({attack_type}) and has been blocked.")
        try:
            with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
                server.login(ADMIN_EMAIL, APP_PASSWORD)
                server.send_message(msg)
        except Exception as e:
            print(f"Failed to send email: {e}")

def block_ip(ip_address, attack_type):
    if ip_address not in blocked_ips:
        blocked_ips[ip_address] = time.time()
        log_attack(ip_address, attack_type)
        send_alert(ip_address, attack_type)

def extract_features(packet):
    try:
        features = [len(packet)]
        if IP in packet:
            features += [packet[IP].ttl, packet[IP].len, packet[IP].proto]
            if TCP in packet:
                features += [
                    packet[TCP].sport, packet[TCP].dport,
                    packet[TCP].seq, packet[TCP].ack,
                    int(packet[TCP].flags)
                ]
            elif UDP in packet:
                features += [packet[UDP].sport, packet[UDP].dport, packet[UDP].len]
        features += [0] * (116 - len(features))
        return np.array(features).reshape(1, -1)
    except:
        return None

def analyze_packet(packet):
    if IP not in packet:
        return

    ip_address = packet[IP].src

    if ip_address == HOST_IP or ip_address.startswith(("127.", "169.254.")):
        return

    if is_safe_ip(ip_address):
        return

    if ip_address in blocked_ips and (time.time() - blocked_ips[ip_address] < COOLDOWN_PERIOD):
        return

    if ip_address in false_positive_ips and (time.time() - false_positive_ips[ip_address] < 3600):
        return

    attack_type = None

    if TCP in packet:
        flags = packet[TCP].flags
        if flags == 2:
            attack_type = "Port Scanning Attack"
        elif flags == 17:
            attack_type = "Stealth Scan Attack"
        elif flags == 0:
            attack_type = "TCP Null Scan Attack"
        elif packet[TCP].dport in [23, 3389]:
            attack_type = "Policy Violation: Access to Restricted Port"

    if not attack_type and ip_address.startswith(("192.168.", "10.", "172.")) and packet[IP].ttl < 20:
        attack_type = "Internal Attack Detected"

    if not attack_type:
        features = extract_features(packet)
        if features is not None:
            try:
                if hasattr(model, 'predict_proba'):
                    prediction = model.predict(features)[0]
                    confidence = model.predict_proba(features)[0][1]
                    if prediction == 1 and confidence >= 0.7:
                        if len(packet) > 1500:
                            attack_type = "DoS Attack Detected (High Confidence)"
                        elif TCP in packet and packet[TCP].flags == 24:
                            attack_type = "Exploit Attempt Detected (High Confidence)"
                        elif packet[IP].ttl > 120:
                            attack_type = "Reconnaissance Activity Detected"
                        else:
                            attack_type = "Generic Threat (High Confidence)"
                    else:
                        false_positive_ips[ip_address] = time.time()
                        with open(LOG_FILE, "a") as f:
                            f.write(f"[{datetime.datetime.now()}] ML Suspicious (Low Confidence) from {ip_address} - Ignored\n")
                        return
                else:
                    prediction = model.predict(features)[0]
                    if prediction == 1:
                        attack_type = "Potential Attack Detected (Basic Model)"
            except Exception as e:
                print(f"ML prediction error: {e}")
                return

    if attack_type:
        block_ip(ip_address, attack_type)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/logs')
def get_logs():
    return jsonify(attack_logs[-100:] if LOG_VISIBLE else [])

@app.route('/blocked_ips')
def get_blocked_ips():
    return jsonify(blocked_ips)

@app.route('/suppress/<ip>')
def suppress_ip(ip):
    false_positive_ips[ip] = time.time()
    return jsonify({"message": f"{ip} suppressed for 1 hour"})

if __name__ == "__main__":
    threading.Thread(target=sniff, kwargs={
        'prn': analyze_packet,
        'store': False,
        'filter': 'ip and (tcp or udp)',
    }, daemon=True).start()

    app.run(debug=True, host='0.0.0.0', port=5000)
