#!/usr/bin/env python3
"""
Network Intrusion Detection System (NIDS)
Real-time IoT traffic analysis with ANN-based threat detection
This version aligns with a 6-feature multiclass model:
Features: [pkts, bytes, dur, rate, sport, dport]
Classes:  ['Normal', 'DoS', 'Reconnaissance', 'Theft']
Highlights:
- Uses the same 6 features as training (IPs removed from model features)
- Live/PCAP: bidirectional flow aggregation with idle splitting
- Simulator emits DoS/Recon/Theft patterns (no DDoS)
- Heuristics present, but with a multiclass model they act only as a light assist
- Fixed PacketSniffer.stop and ensured sniffer stops when worker stops
- ADDED: File-based communication with NS-3 for Dynamic Rerouting and Proactive Verification.
"""
import sys
import os
import json
import time
import random
import warnings
import subprocess
import ctypes
from datetime import datetime
from typing import Dict, List, Tuple, Optional
warnings.filterwarnings('ignore')
# Core libs
import numpy as np
from sklearn.preprocessing import StandardScaler
import joblib
import tensorflow as tf
from tensorflow import keras
# PyQt5
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
    QLabel, QPushButton, QTableWidget, QTableWidgetItem, QTextEdit, QGroupBox,
    QTabWidget, QSpinBox, QCheckBox, QSplitter, QComboBox, QProgressBar, QFileDialog
)
from PyQt5.QtCore import QThread, pyqtSignal, QTimer, Qt
from PyQt5.QtGui import QFont, QColor, QPainter, QPen
import pyqtgraph as pg
from scapy.all import sniff, get_if_list, IP, TCP, UDP, rdpcap
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure
import matplotlib.animation as animation

# ========================= Constants =========================
# 6 features to match the trained model
SELECTED_FEATURES = [
    'pkts',  # packet count in flow
    'bytes', # total bytes in flow
    'dur',   # flow duration (seconds)
    'rate',  # packet rate (packets/sec)
    'sport', # source port
    'dport'  # destination port
]
DEFAULT_MODEL_PATH = 'ann_model.h5'
DEFAULT_SCALER_PATH = 'scaler.pkl'
DEFAULT_CLASS_NAMES_PATH = 'class_names.json'
# File-based IPC for NS-3
COMMAND_FILE = 'nids_commands.json'  # Python writes commands here for NS-3
EVENT_FILE = 'nids_events.json'      # NS-3 writes events here for Python
# Final classes (no DDoS)
ATTACK_TYPES = ['Normal', 'DoS', 'Reconnaissance', 'Theft']

# ========================= Utilities =========================
def clamp(val, lo, hi):
    return max(lo, min(hi, val))

def ip_int_to_str(x: int) -> str:
    try:
        x = int(x) & 0xFFFFFFFF
        return f"{(x >> 24) & 255}.{(x >> 16) & 255}.{(x >> 8) & 255}.{x & 255}"
    except Exception:
        return "0.0.0.0"

def ip_str_to_int(s: str) -> int:
    try:
        parts = s.split('.')
        return (int(parts[0]) << 24) + (int(parts[1]) << 16) + (int(parts[2]) << 8) + int(parts[3])
    except Exception:
        return 0

def safe_int(x, default=0):
    try:
        return int(float(x))
    except Exception:
        try:
            return int(x)
        except Exception:
            return default

def safe_float(x, default=0.0):
    try:
        return float(x)
    except Exception:
        return default

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def align_features(x: np.ndarray, target_dim: int) -> np.ndarray:
    if x.ndim == 1:
        x = x.reshape(1, -1)
    n = x.shape[1]
    if n == target_dim:
        return x
    if n > target_dim:
        return x[:, :target_dim]
    pad = np.zeros((x.shape[0], target_dim - n), dtype=x.dtype)
    return np.hstack([x, pad])

def normalize_class_name(name: str) -> str:
    s = str(name).strip().lower()
    if 'normal' in s or s == '0':
        return 'Normal'
    # collapse any ddos into DoS
    if 'ddos' in s:
        return 'DoS'
    if 'dos' in s and 'ddos' not in s:
        return 'DoS'
    if 'recon' in s or 'scan' in s:
        return 'Reconnaissance'
    if 'theft' in s or 'exfil' in s or 'data' in s:
        return 'Theft'
    return 'DoS'

def infer_attack_type_from_features(features: Dict) -> str:
    """Lightweight heuristic (used mainly if running a binary model)."""
    pkts = safe_float(features.get('pkts', 0))
    bytes_total = safe_float(features.get('bytes', 0))
    dur = safe_float(features.get('dur', 0))
    rate = safe_float(features.get('rate', 0))
    # Theft first
    if bytes_total >= 100_000 or (dur >= 60 and pkts >= 200):
        return 'Theft'
    # DoS (includes any extreme-rate bursts)
    if rate >= 300 or pkts >= 5000:
        return 'DoS'
    if (rate >= 20 and dur >= 5) or (pkts >= 1000 and dur >= 30):
        return 'DoS'
    # Recon
    if (pkts <= 5 and bytes_total <= 400 and dur <= 1.0):
        return 'Reconnaissance'
    return 'DoS'

# ========================= Route Manager =========================
class RouteManager:
    def __init__(self, log_callback):
        self.blocked_ips = set()
        self.log = log_callback
        self.is_admin = is_admin()
        if not self.is_admin:
            self.log("Not running as Administrator. Real-time IP blocking will be disabled.", "WARNING")

    def block_ip(self, ip_str: str):
        if not self.is_admin:
            return
        if ip_str in self.blocked_ips or ip_str == "0.0.0.0":
            return
        try:
            command = f"route ADD {ip_str} MASK 255.255.255.255 0.0.0.0"
            subprocess.run(command, check=True, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.blocked_ips.add(ip_str)
            self.log(f"Blocked IP: {ip_str}", "ROUTE")
        except subprocess.CalledProcessError as e:
            self.log(f"Failed to block IP {ip_str}: {e.stderr.decode()}", "ERROR")

    def unblock_ip(self, ip_str: str):
        if not self.is_admin or ip_str not in self.blocked_ips:
            return
        try:
            command = f"route DELETE {ip_str}"
            subprocess.run(command, check=True, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.blocked_ips.remove(ip_str)
            self.log(f"Unblocked IP: {ip_str}", "ROUTE")
        except subprocess.CalledProcessError as e:
            self.log(f"Failed to unblock IP {ip_str}: {e.stderr.decode()}", "ERROR")

    def cleanup(self):
        if not self.is_admin:
            return
        for ip in list(self.blocked_ips):
            self.unblock_ip(ip)

# ========================= Worker =========================
class NetworkTrafficWorker(QThread):
    packet_received = pyqtSignal(dict)
    prediction_made = pyqtSignal(dict)

    def __init__(self):
        super().__init__()
        self.traffic_simulator = TrafficSimulator()
        self.sniffer: Optional[PacketSniffer] = None
        self.source = "Simulator"
        self.interface = None
        self.pcap_file = None
        self.idle_timeout = 0.2  # keep tiny scans tiny
        self.idle_timeout_small = 0.25  # split tiny flows quickly
        self.idle_timeout_long = 5.0    # only split big flows after long idle
        self.feature_extractor = FeatureExtractor()
        self.ann_predictor = ANNPredictor()
        self.is_running = False
        self.detection_threshold = 0.5
        # Flow tracking for live/pcap
        self.flow_tracker = {}

    def run(self):
        self.is_running = True
        if self.source == "Live Capture" and self.interface:
            self.sniffer = PacketSniffer(self.interface)
            self.sniffer.packet_sniffed.connect(self.process_scapy_packet)
            self.sniffer.start()
            while self.is_running:
                time.sleep(0.1)
        elif self.source == "PCAP File" and self.pcap_file:
            try:
                packets = rdpcap(self.pcap_file)
                for packet in packets:
                    if not self.is_running:
                        break
                    self.process_scapy_packet(packet)
                    time.sleep(0.0005)
            except Exception as e:
                print(f"PCAP processing error: {e}")
            self.is_running = False
        else:  # Simulator
            while self.is_running:
                try:
                    packet = self.traffic_simulator.generate_packet()
                    self.process_packet_dict(packet)
                    time.sleep(1.0 / self.traffic_simulator.packet_rate)
                except Exception as e:
                    print(f"Simulator error: {e}")
                    time.sleep(0.1)

    def process_scapy_packet(self, scapy_packet):
        """Convert scapy packet to feature dict"""
        if not IP in scapy_packet:
            return
        packet_dict = self.scapy_to_dict(scapy_packet)
        if packet_dict:
            self.process_packet_dict(packet_dict)

    def scapy_to_dict(self, pkt) -> Optional[Dict]:
        """Convert scapy packet to features with bidirectional aggregation."""
        if not pkt.haslayer(IP):
            return None
        ts = float(getattr(pkt, 'time', time.time()))
        ip_layer = pkt[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        saddr = ip_str_to_int(src_ip)
        daddr = ip_str_to_int(dst_ip)
        proto_map = {1: 'icmp', 6: 'tcp', 17: 'udp'}
        proto = proto_map.get(ip_layer.proto, 'unknown')
        sport, dport = 0, 0
        if pkt.haslayer(TCP):
            sport = int(pkt[TCP].sport); dport = int(pkt[TCP].dport)
        elif pkt.haslayer(UDP):
            sport = int(pkt[UDP].sport); dport = int(pkt[UDP].dport)
        # Canonical, bidirectional 5-tuple for aggregation
        a = (saddr, sport)
        b = (daddr, dport)
        flow_key = (a, b, proto) if a <= b else (b, a, proto)
        length = len(pkt)
        entry = self.flow_tracker.get(flow_key)
        if entry is None:
            entry = {
                'start_time': ts,
                'last_seen': ts,
                'packet_count': 1,
                'total_bytes': length,
                # keep first-seen direction for display
                'first_src': saddr,
                'first_dst': daddr,
                'first_sport': sport,
                'first_dport': dport,
            }
            self.flow_tracker[flow_key] = entry
            dur = 0.001; pkts = 1; bytes_total = length
        else:
            # Smart split: preserve sustained DoS, keep Recon tiny
            gap = ts - entry['last_seen']
            if gap > self.idle_timeout_long:
                # always split if idle very long
                entry['start_time'] = ts
                entry['packet_count'] = 0
                entry['total_bytes'] = 0
            elif gap > self.idle_timeout_small:
                # split only if the flow was tiny (likely a recon burst)
                if entry['packet_count'] <= 5 and entry['total_bytes'] <= 400:
                    entry['start_time'] = ts
                    entry['packet_count'] = 0
                    entry['total_bytes'] = 0
            entry['packet_count'] += 1
            entry['total_bytes'] += length
            entry['last_seen'] = ts
            dur = max(ts - entry['start_time'], 0.001)
            pkts = entry['packet_count']
            bytes_total = entry['total_bytes']
        rate = pkts / max(dur, 0.001)
        # Cleanup flows inactive > 2 minutes
        if len(self.flow_tracker) > 20000:
            cutoff = ts - 120
            self.flow_tracker = {
                k: v for k, v in self.flow_tracker.items()
                if v.get('last_seen', v['start_time']) > cutoff
            }
        return {
            'pkts': float(pkts),
            'bytes': float(bytes_total),
            'dur': float(dur),
            'rate': float(rate),
            # Note: IPs are kept only for UI/logging; not used in model features
            'saddr': float(entry['first_src']),
            'daddr': float(entry['first_dst']),
            'sport': float(entry['first_sport']),
            'dport': float(entry['first_dport']),
            'proto': proto,
            'timestamp': datetime.now(),
            'attack_type': 'Unknown'
        }

    def process_packet_dict(self, packet: Dict):
        """Process packet through ML pipeline"""
        try:
            self.packet_received.emit(packet)
            t0 = time.time()
            features = self.feature_extractor.extract_features(packet)  # 6 features only
            pred_class, confidence, probabilities = self.ann_predictor.predict(features)
            t1 = time.time()
            heur_type = infer_attack_type_from_features(packet)
            heur_intrusion = heur_type in ('DoS', 'Theft', 'Reconnaissance')
            if self.ann_predictor.is_binary:
                # Heuristics can trigger intrusion even if model confidence is low
                is_intrusion = (confidence >= self.detection_threshold) or heur_intrusion
                predicted_attack_type = heur_type if is_intrusion else 'Normal'
            else:
                predicted_attack_type = normalize_class_name(pred_class)
                # Assist only if model says Normal and confidence is low
                if predicted_attack_type == 'Normal' and heur_intrusion and confidence < 0.7:
                    predicted_attack_type = heur_type
                is_intrusion = (predicted_attack_type != 'Normal')
            detection_delay = (datetime.now() - packet['timestamp']).total_seconds() * 1000.0
            processing_time = (t1 - t0) * 1000.0
            prediction_result = {
                'timestamp': packet['timestamp'],
                'predicted_class': pred_class,
                'predicted_attack_type': predicted_attack_type,
                'confidence': float(confidence),
                'probabilities': probabilities,
                'is_intrusion': bool(is_intrusion),
                'detection_delay_ms': detection_delay,
                'processing_time_ms': processing_time,
                'ground_truth_attack': packet.get('attack_type', 'Unknown'),
                'packet_info': {
                    'src_ip_int': safe_int(packet.get('saddr', 0)),
                    'dst_ip_int': safe_int(packet.get('daddr', 0)),
                    'src_ip_str': ip_int_to_str(packet.get('saddr', 0)),
                    'dst_ip_str': ip_int_to_str(packet.get('daddr', 0)),
                    'sport': safe_int(packet.get('sport', 0)),
                    'dport': safe_int(packet.get('dport', 0)),
                    'bytes': safe_float(packet.get('bytes', 0)),
                    'packet_rate': safe_float(packet.get('rate', 0)),
                    'flow_duration': safe_float(packet.get('dur', 0)),
                    'packet_count': safe_float(packet.get('pkts', 0)),
                }
            }
            self.prediction_made.emit(prediction_result)
        except Exception as e:
            print(f"Processing error: {e}")

    def stop(self):
        self.is_running = False
        if self.sniffer:
            self.sniffer.stop()
            self.sniffer = None
        self.quit()
        self.wait(2)

# ========================= Feature Extractor =========================
class FeatureExtractor:
    def __init__(self, scaler_path: str = DEFAULT_SCALER_PATH):
        self.scaler_path = scaler_path
        self.scaler = StandardScaler()
        self.feature_names = SELECTED_FEATURES[:]  # 6 features
        self.is_fitted = False
        self._load_or_init_scaler()

    def _load_or_init_scaler(self):
        try:
            if os.path.exists(self.scaler_path):
                self.scaler = joblib.load(self.scaler_path)
                self.is_fitted = True
                print(f"Loaded scaler from {self.scaler_path}")
            else:
                # Initialize scaler with synthetic samples from the simulator using ONLY these 6 features
                samples = []
                simulator = TrafficSimulator()
                for _ in range(1000):
                    packet = simulator.generate_packet()
                    samples.append([float(packet.get(f, 0.0)) for f in self.feature_names])
                samples = np.array(samples, dtype=float)
                self.scaler.fit(samples)
                self.is_fitted = True
                print("Initialized scaler with realistic synthetic data (6 features)")
        except Exception as e:
            print(f"Scaler error: {e}")
            self.is_fitted = False

    def extract_features(self, packet: Dict) -> np.ndarray:
        # Build feature vector strictly in the order of self.feature_names (6 features)
        features = []
        for feature_name in self.feature_names:
            if feature_name in packet:
                val = safe_float(packet[feature_name])
            else:
                # Fallback mappings for compatibility
                if feature_name == 'pkts' and 'packet_count' in packet:
                    val = safe_float(packet['packet_count'])
                elif feature_name == 'bytes' and 'packet_size' in packet:
                    val = safe_float(packet['packet_size'])
                elif feature_name == 'dur' and 'flow_duration' in packet:
                    val = safe_float(packet['flow_duration'])
                elif feature_name == 'rate' and 'packet_rate' in packet:
                    val = safe_float(packet['packet_rate'])
                elif feature_name == 'sport' and 'src_port' in packet:
                    val = safe_float(packet['src_port'])
                elif feature_name == 'dport' and 'dst_port' in packet:
                    val = safe_float(packet['dst_port'])
                else:
                    val = 0.0
            features.append(val)
        x = np.array(features, dtype=float).reshape(1, -1)
        if self.is_fitted:
            try:
                x = self.scaler.transform(x)  # scaler was trained on 6 features
            except Exception as e:
                print(f"Scaling error: {e}")
        return x.flatten()

# ========================= ANN Predictor =========================
class ANNPredictor:
    def __init__(self, model_path: str = DEFAULT_MODEL_PATH, class_names_path: str = DEFAULT_CLASS_NAMES_PATH):
        self.model_path = model_path
        self.class_names_path = class_names_path
        self.model = None
        self.input_dim = len(SELECTED_FEATURES)
        self.output_dim = 2
        self.is_binary = True
        self.class_names = ['Normal', 'Attack']
        self.load_model()

    def load_model(self):
        try:
            if os.path.exists(self.model_path):
                self.model = keras.models.load_model(self.model_path)
                self.input_dim = int(self.model.input_shape[-1])
                out_dim = self.model.output_shape[-1]
                self.output_dim = int(out_dim if isinstance(out_dim, int) else 1)
                self.is_binary = (self.output_dim == 1)
                if not self.is_binary:
                    # Load class names for multiclass
                    if os.path.exists(self.class_names_path):
                        with open(self.class_names_path, 'r') as f:
                            names = json.load(f)
                        if isinstance(names, list) and len(names) == self.output_dim:
                            # normalize (collapse any ddos to DoS)
                            self.class_names = [normalize_class_name(n) for n in names]
                        else:
                            self.class_names = ATTACK_TYPES[:self.output_dim]
                    else:
                        self.class_names = ATTACK_TYPES[:self.output_dim]
                else:
                    self.class_names = ['Normal', 'Attack']
                print(f"Loaded model: input_dim={self.input_dim}, output_dim={self.output_dim}, binary={self.is_binary}")
            else:
                print(f"Model file {self.model_path} not found. Creating dummy model...")
                self.create_dummy_model()
        except Exception as e:
            print(f"Model load error: {e}. Creating dummy model...")
            self.create_dummy_model()

    def create_dummy_model(self):
        """Create a dummy binary model for testing"""
        self.input_dim = len(SELECTED_FEATURES)
        self.is_binary = True
        self.output_dim = 1
        self.class_names = ['Normal', 'Attack']
        self.model = keras.Sequential([
            keras.layers.Dense(32, activation='relu', input_shape=(self.input_dim,)),
            keras.layers.Dropout(0.2),
            keras.layers.Dense(16, activation='relu'),
            keras.layers.Dropout(0.1),
            keras.layers.Dense(1, activation='sigmoid')
        ])
        self.model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])
        dummy_x = np.random.random((256, self.input_dim)).astype(np.float32)
        dummy_y = (np.random.random((256, 1)) > 0.8).astype(np.float32)
        self.model.fit(dummy_x, dummy_y, epochs=1, verbose=0)
        print(f"Created dummy binary model (input_dim={self.input_dim})")

    def predict(self, features: np.ndarray) -> Tuple[str, float, np.ndarray]:
        try:
            if features.ndim == 1:
                features = features.reshape(1, -1)
            features = align_features(features, self.input_dim)
            pred = self.model.predict(features, verbose=0)
            if self.is_binary:
                p_attack = float(np.clip(pred[0][0], 0.0, 1.0))
                predicted_class = 'Attack' if p_attack >= 0.5 else 'Normal'
                probs = np.array([1.0 - p_attack, p_attack], dtype=float)
                return predicted_class, p_attack, probs
            else:
                probs = pred[0]
                idx = int(np.argmax(probs))
                predicted_class = self.class_names[idx] if idx < len(self.class_names) else f"Class_{idx}"
                conf = float(probs[idx])
                return predicted_class, conf, probs
        except Exception as e:
            print(f"Prediction error: {e}")
            return 'Normal', 0.0, np.array([1.0, 0.0])

# ========================= Traffic Simulator =========================
class TrafficSimulator:
    """Generate realistic network traffic aligned with Bot-IoT dataset features (6-feature model)."""
    def __init__(self):
        self.is_running = False
        self.attack_probability = 0.15   # raise a bit while testing
        self.packet_rate = 50
        # No DDoS in your dataset
        self.attack_types = ['DoS', 'Reconnaissance', 'Theft', 'Normal']
        # Optional weighting among attack types (sum to 1.0)
        self.attack_weights = [('DoS', 0.40), ('Reconnaissance', 0.25), ('Theft', 0.35)]
        # Common IP ranges for UI/logging only
        self.common_ips = [
            '192.168.1.', '192.168.0.', '10.0.0.', '172.16.0.',
            '192.168.100.', '10.1.1.', '172.20.0.'
        ]

    def _generate_realistic_ip(self) -> int:
        base = random.choice(self.common_ips)
        last_octet = random.randint(1, 254)
        ip_str = base + str(last_octet)
        return ip_str_to_int(ip_str)

    def _choose_attack_type(self) -> str:
        types, weights = zip(*self.attack_weights)
        return random.choices(types, weights=weights, k=1)[0]

    def generate_packet(self) -> Dict:
        is_attack = random.random() < self.attack_probability
        attack_type = self._choose_attack_type() if is_attack else 'Normal'
        # Default values (will be overridden per type)
        saddr = self._generate_realistic_ip()
        daddr = self._generate_realistic_ip()
        sport = random.randint(1024, 65535)
        dport = random.randint(1, 65535)
        if attack_type == 'Normal':
            # Make Normal clearly distinct from Recon
            pkts = random.randint(10, 60)
            bytes_per_pkt = random.randint(300, 900)
            bytes_total = pkts * bytes_per_pkt
            dur = random.uniform(1.0, 20.0)
            rate = pkts / dur
            dport = random.choice([53, 80, 123, 443, 8080])
        elif attack_type == 'DoS':
            pkts = random.randint(400, 2000)
            bytes_total = pkts * random.randint(500, 2000)
            dur = random.uniform(10.0, 120.0)
            rate = pkts / dur
            dport = random.choice([80, 443, 22, 21])
        elif attack_type == 'Reconnaissance':
            pkts = random.randint(1, 4)
            bytes_total = pkts * random.randint(60, 120)
            dur = random.uniform(0.005, 0.3)
            rate = pkts / max(dur, 0.001)
            dport = random.randint(1, 65535)
            sport = random.randint(30000, 65535)
        elif attack_type == 'Theft':
            pkts = random.randint(300, 3000)
            bytes_total = pkts * random.randint(1000, 8000)
            dur = random.uniform(60.0, 600.0)
            rate = pkts / dur
            dport = random.choice([21, 22, 80, 443, 2049])
        # Clamp for stability
        pkts = int(clamp(pkts, 1, 5000))
        bytes_total = float(clamp(bytes_total, 60, 5_000_000))
        dur = float(clamp(dur, 0.001, 600.0))
        rate = float(clamp(rate, 0.1, 10000.0))
        sport = int(clamp(sport, 1, 65535))
        dport = int(clamp(dport, 1, 65535))
        return {
            # Model features (6)
            'pkts': float(pkts),
            'bytes': float(bytes_total),
            'dur': float(dur),
            'rate': float(rate),
            'sport': float(sport),
            'dport': float(dport),
            # Metadata for UI/logging
            'saddr': float(saddr),
            'daddr': float(daddr),
            'timestamp': datetime.now(),
            'attack_type': attack_type,
            'proto': random.choice(['tcp', 'udp']),
            # Legacy compatibility
            'packet_size': float(bytes_total),
            'src_ip': float(saddr),
            'dst_ip': float(daddr),
            'src_port': float(sport),
            'dst_port': float(dport),
        }

# ========================= Live Packet Sniffer =========================
class PacketSniffer(QThread):
    packet_sniffed = pyqtSignal(object)

    def __init__(self, interface: str):
        super().__init__()
        self.interface = interface
        self.is_running = False

    def run(self):
        self.is_running = True
        print(f"Starting packet capture on interface: {self.interface}")
        sniff(iface=self.interface, prn=self.on_packet, stop_filter=lambda p: not self.is_running)

    def on_packet(self, packet):
        self.packet_sniffed.emit(packet)

    def stop(self):
        self.is_running = False
        self.quit()
        self.wait()

# ========================= GUI Widgets =========================
class MetricsWidget(QWidget):
    def __init__(self):
        super().__init__()
        self.setup_ui()
        self.reset_metrics()

    def setup_ui(self):
        layout = QGridLayout()
        self.total_packets_label = QLabel("0")
        self.intrusions_detected_label = QLabel("0")
        self.accuracy_label = QLabel("0.00%")
        self.precision_label = QLabel("0.00%")
        self.recall_label = QLabel("0.00%")
        self.f1_label = QLabel("0.00%")
        self.avg_delay_label = QLabel("0.00 ms")
        font = QFont("Arial", 12, QFont.Bold)
        for label in [self.total_packets_label, self.intrusions_detected_label,
                      self.accuracy_label, self.precision_label,
                      self.recall_label, self.f1_label, self.avg_delay_label]:
            label.setFont(font)
            label.setAlignment(Qt.AlignCenter)
            label.setStyleSheet("color: #2E86AB; background-color: #F8F9FA; "
                                "border: 1px solid #E9ECEF; border-radius: 5px; "
                                "padding: 10px;")
        layout.addWidget(QLabel("Total Packets:"), 0, 0)
        layout.addWidget(self.total_packets_label, 0, 1)
        layout.addWidget(QLabel("Intrusions Detected:"), 0, 2)
        layout.addWidget(self.intrusions_detected_label, 0, 3)
        layout.addWidget(QLabel("Accuracy:"), 1, 0)
        layout.addWidget(self.accuracy_label, 1, 1)
        layout.addWidget(QLabel("Precision:"), 1, 2)
        layout.addWidget(self.precision_label, 1, 3)
        layout.addWidget(QLabel("Recall:"), 2, 0)
        layout.addWidget(self.recall_label, 2, 1)
        layout.addWidget(QLabel("F1-score:"), 2, 2)
        layout.addWidget(self.f1_label, 2, 3)
        layout.addWidget(QLabel("Avg Detection Delay:"), 3, 0)
        layout.addWidget(self.avg_delay_label, 3, 1)
        self.setLayout(layout)

    def reset_metrics(self):
        self.total_packets = 0
        self.intrusions_detected = 0
        self.tp = 0
        self.fp = 0
        self.tn = 0
        self.fn = 0
        self.delay_sum_ms = 0.0
        self.delay_count = 0

    def update_metrics(self, prediction_result: Dict):
        self.total_packets += 1
        if prediction_result['is_intrusion']:
            self.intrusions_detected += 1
        ground_truth = prediction_result.get('ground_truth_attack')
        if ground_truth != 'Unknown':
            gt_attack = 0 if ground_truth == 'Normal' else 1
            pred_attack = 1 if prediction_result.get('is_intrusion') else 0
            if gt_attack == 1 and pred_attack == 1:
                self.tp += 1
            elif gt_attack == 0 and pred_attack == 0:
                self.tn += 1
            elif gt_attack == 0 and pred_attack == 1:
                self.fp += 1
            elif gt_attack == 1 and pred_attack == 0:
                self.fn += 1
            total = self.tp + self.tn + self.fp + self.fn
            accuracy = (self.tp + self.tn) / total * 100.0 if total > 0 else 0.0
            precision = self.tp / (self.tp + self.fp) * 100.0 if (self.tp + self.fp) > 0 else 0.0
            recall = self.tp / (self.tp + self.fn) * 100.0 if (self.tp + self.fn) > 0 else 0.0
            f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
            self.accuracy_label.setText(f"{accuracy:.2f}%")
            self.precision_label.setText(f"{precision:.2f}%")
            self.recall_label.setText(f"{recall:.2f}%")
            self.f1_label.setText(f"{f1:.2f}%")
        else:
            self.accuracy_label.setText("N/A")
            self.precision_label.setText("N/A")
            self.recall_label.setText("N/A")
            self.f1_label.setText("N/A")
        delay_ms = float(prediction_result.get('detection_delay_ms', 0.0))
        self.delay_sum_ms += delay_ms
        self.delay_count += 1
        avg_delay = self.delay_sum_ms / self.delay_count if self.delay_count > 0 else 0.0
        self.total_packets_label.setText(str(self.total_packets))
        self.intrusions_detected_label.setText(str(self.intrusions_detected))
        self.avg_delay_label.setText(f"{avg_delay:.2f} ms")

class AlertWidget(QWidget):
    def __init__(self):
        super().__init__()
        self.setup_ui()
        self.alerts = []

    def setup_ui(self):
        layout = QVBoxLayout()
        title = QLabel("Security Alerts")
        title.setFont(QFont("Arial", 14, QFont.Bold))
        title.setStyleSheet("color: #D32F2F; margin-bottom: 10px;")
        layout.addWidget(title)
        self.alert_table = QTableWidget()
        self.alert_table.setColumnCount(7)
        self.alert_table.setHorizontalHeaderLabels([
            "Time", "Attack Type", "Confidence", "Source IP", "Target IP", "Target Port", "Action"
        ])
        self.alert_table.horizontalHeader().setStretchLastSection(True)
        self.alert_table.setAlternatingRowColors(True)
        layout.addWidget(self.alert_table)
        self.setLayout(layout)

    def add_alert(self, prediction_result: Dict, action: str):
        # Removed the condition 'if not prediction_result['is_intrusion']: return'
        # so that ALL events (Normal and Attack) are logged.
        alert = {
            'timestamp': prediction_result['timestamp'],
            'attack_type': prediction_result.get('predicted_attack_type', 'Attack'),
            'confidence': prediction_result['confidence'],
            'packet_info': prediction_result['packet_info'],
            'action': action
        }
        self.alerts.append(alert)
        row = self.alert_table.rowCount()
        self.alert_table.insertRow(row)
        time_str = alert['timestamp'].strftime("%H:%M:%S")
        src_ip = alert['packet_info'].get('src_ip_str', '0.0.0.0')
        dst_ip = alert['packet_info'].get('dst_ip_str', '0.0.0.0')
        self.alert_table.setItem(row, 0, QTableWidgetItem(time_str))
        self.alert_table.setItem(row, 1, QTableWidgetItem(alert['attack_type']))
        self.alert_table.setItem(row, 2, QTableWidgetItem(f"{alert['confidence']:.3f}"))
        self.alert_table.setItem(row, 3, QTableWidgetItem(src_ip))
        self.alert_table.setItem(row, 4, QTableWidgetItem(dst_ip))
        self.alert_table.setItem(row, 5, QTableWidgetItem(str(alert['packet_info']['dport'])))
        self.alert_table.setItem(row, 6, QTableWidgetItem(action))
        
        # Set row background color: Red for intrusion, Green for normal.
        if prediction_result['is_intrusion']:
            row_color = QColor(255, 0, 0, 30)  # Semi-transparent red
        else:
            row_color = QColor(0, 255, 0, 30)  # Semi-transparent green

        for col in range(self.alert_table.columnCount()):
            item = self.alert_table.item(row, col)
            if item:
                item.setBackground(row_color)

        self.alert_table.scrollToBottom()
        if self.alert_table.rowCount() > 2000:
            self.alert_table.removeRow(0)

class RoutesWidget(QWidget):
    def __init__(self):
        super().__init__()
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout()
        title = QLabel("Packet Routes")
        title.setFont(QFont("Arial", 14, QFont.Bold))
        layout.addWidget(title)
        self.routes_table = QTableWidget()
        self.routes_table.setColumnCount(7)  # Added "Verification" column
        self.routes_table.setHorizontalHeaderLabels([
            "Time", "Type", "Confidence", "Source IP", "Destination IP", "Route", "Action"
        ])
        self.routes_table.horizontalHeader().setStretchLastSection(True)
        self.routes_table.setAlternatingRowColors(True)
        layout.addWidget(self.routes_table)
        self.setLayout(layout)

    def add_route(self, prediction_result: Dict, route_nodes: List[str], action: str):
        row = self.routes_table.rowCount()
        self.routes_table.insertRow(row)
        time_str = prediction_result['timestamp'].strftime("%H:%M:%S")
        atype = prediction_result.get('predicted_attack_type', prediction_result['predicted_class'])
        conf = prediction_result['confidence']
        src_ip = prediction_result['packet_info'].get('src_ip_str', '0.0.0.0')
        dst_ip = prediction_result['packet_info'].get('dst_ip_str', '0.0.0.0')
        route_str = " → ".join(route_nodes)
        self.routes_table.setItem(row, 0, QTableWidgetItem(time_str))
        self.routes_table.setItem(row, 1, QTableWidgetItem(atype))
        self.routes_table.setItem(row, 2, QTableWidgetItem(f"{conf:.3f}"))
        self.routes_table.setItem(row, 3, QTableWidgetItem(src_ip))
        self.routes_table.setItem(row, 4, QTableWidgetItem(dst_ip))
        self.routes_table.setItem(row, 5, QTableWidgetItem(route_str))
        self.routes_table.setItem(row, 6, QTableWidgetItem(action))
        self.routes_table.scrollToBottom()
        if self.routes_table.rowCount() > 500:
            self.routes_table.removeRow(0)

class TrafficVisualizationWidget(QWidget):
    def __init__(self):
        super().__init__()
        self.setup_ui()
        self.max_points = 200

    def setup_ui(self):
        layout = QVBoxLayout()
        title = QLabel("Real-time Traffic Analysis")
        title.setFont(QFont("Arial", 14, QFont.Bold))
        layout.addWidget(title)
        self.plot_widget = pg.PlotWidget()
        self.plot_widget.setBackground('w')
        self.plot_widget.setLabel('left', 'Packets (binary label)')
        self.plot_widget.setLabel('bottom', 'Time (seconds)')
        self.plot_widget.showGrid(x=True, y=True)
        self.normal_curve = self.plot_widget.plot(pen='g', name='Normal Traffic')
        self.attack_curve = self.plot_widget.plot(pen='r', name='Attack Traffic')
        self.plot_widget.addLegend()
        layout.addWidget(self.plot_widget)
        confidence_title = QLabel("Attack Confidence")
        confidence_title.setFont(QFont("Arial", 12, QFont.Bold))
        layout.addWidget(confidence_title)
        self.confidence_widget = pg.PlotWidget()
        self.confidence_widget.setBackground('w')
        self.confidence_widget.setLabel('left', 'Confidence')
        self.confidence_widget.setLabel('bottom', 'Time (seconds)')
        self.confidence_widget.setYRange(0, 1)
        self.confidence_curve = self.confidence_widget.plot(pen='b', name='Confidence')
        layout.addWidget(self.confidence_widget)
        self.setLayout(layout)
        self.normal_data = []
        self.attack_data = []
        self.confidence_data = []
        self.time_data = []
        self.start_time = time.time()

    def update_plots(self, prediction_result: Dict):
        current_time = time.time() - self.start_time
        self.time_data.append(current_time)
        self.confidence_data.append(float(prediction_result['confidence']))
        if prediction_result['is_intrusion']:
            self.attack_data.append(1)
            self.normal_data.append(0)
        else:
            self.attack_data.append(0)
            self.normal_data.append(1)
        if len(self.time_data) > self.max_points:
            self.time_data = self.time_data[-self.max_points:]
            self.normal_data = self.normal_data[-self.max_points:]
            self.attack_data = self.attack_data[-self.max_points:]
            self.confidence_data = self.confidence_data[-self.max_points:]
        self.normal_curve.setData(self.time_data, self.normal_data)
        self.attack_curve.setData(self.time_data, self.attack_data)
        self.confidence_curve.setData(self.time_data, self.confidence_data)

class ConfigurationWidget(QWidget):
    def __init__(self):
        super().__init__()
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout()
        config_group = QGroupBox("System Configuration")
        config_layout = QGridLayout()
        config_layout.addWidget(QLabel("Traffic Source:"), 0, 0)
        self.source_combo = QComboBox()
        self.source_combo.addItems(["Simulator", "Live Capture", "PCAP File"])
        config_layout.addWidget(self.source_combo, 0, 1)
        self.interface_label = QLabel("Network Interface:")
        config_layout.addWidget(self.interface_label, 1, 0)
        self.interface_combo = QComboBox()
        config_layout.addWidget(self.interface_combo, 1, 1)
        self.refresh_interfaces_button = QPushButton("Refresh")
        config_layout.addWidget(self.refresh_interfaces_button, 1, 2)
        self.pcap_file_label = QLabel("PCAP File:")
        config_layout.addWidget(self.pcap_file_label, 2, 0)
        self.pcap_file_path_label = QLabel("No file selected.")
        self.pcap_file_path_label.setStyleSheet("font-style: italic;")
        config_layout.addWidget(self.pcap_file_path_label, 2, 1)
        self.browse_pcap_button = QPushButton("Browse...")
        config_layout.addWidget(self.browse_pcap_button, 2, 2)
        self.simulator_group = QGroupBox("Simulator Settings")
        simulator_layout = QGridLayout()
        simulator_layout.addWidget(QLabel("Packet Rate (pps):"), 0, 0)
        self.packet_rate_spin = QSpinBox()
        self.packet_rate_spin.setRange(1, 2000)
        self.packet_rate_spin.setValue(50)
        simulator_layout.addWidget(self.packet_rate_spin, 0, 1)
        simulator_layout.addWidget(QLabel("Attack Probability:"), 1, 0)
        self.attack_prob_spin = QSpinBox()
        self.attack_prob_spin.setRange(0, 100)
        self.attack_prob_spin.setValue(10)
        self.attack_prob_spin.setSuffix("%")
        simulator_layout.addWidget(self.attack_prob_spin, 1, 1)
        self.simulator_group.setLayout(simulator_layout)
        config_layout.addWidget(self.simulator_group, 3, 0, 1, 3)
        config_layout.addWidget(QLabel("Detection Threshold:"), 4, 0)
        self.threshold_spin = QSpinBox()
        self.threshold_spin.setRange(1, 99)
        self.threshold_spin.setValue(50)
        self.threshold_spin.setSuffix("%")
        config_layout.addWidget(self.threshold_spin, 4, 1)
        self.auto_block_check = QCheckBox("Auto-block detected intrusions")
        config_layout.addWidget(self.auto_block_check, 5, 0, 1, 2)
        config_layout.addWidget(QLabel("Reroute Mode:"), 6, 0)
        self.reroute_mode_combo = QComboBox()
        self.reroute_mode_combo.addItems(["Smart", "Sinkhole", "Honeypot", "Drop", "Forward Only"])
        config_layout.addWidget(self.reroute_mode_combo, 6, 1)
        config_group.setLayout(config_layout)
        layout.addWidget(config_group)
        model_group = QGroupBox("Model Information")
        model_layout = QVBoxLayout()
        self.model_info_text = QTextEdit()
        self.model_info_text.setMaximumHeight(220)
        self.model_info_text.setReadOnly(True)
        self.model_info_text.setText("""
6 Model Features:
• pkts: Number of packets in flow
• bytes: Total bytes in flow
• dur: Flow duration (seconds)
• rate: Packet rate (packets/sec)
• sport: Source port number
• dport: Destination port number
Model Classes:
• Normal, DoS, Reconnaissance, Theft
• Heuristics assist only when confidence is low or in binary mode
        """.strip())
        model_layout.addWidget(self.model_info_text)
        model_group.setLayout(model_layout)
        layout.addWidget(model_group)
        layout.addStretch()
        self.setLayout(layout)

class NetworkCanvas(FigureCanvas):
    def __init__(self, parent=None, width=5, height=4, dpi=100):
        self.fig = Figure(figsize=(width, height), dpi=dpi)
        self.axes = self.fig.add_subplot(111)
        super().__init__(self.fig)
        self.setParent(parent)

        self.nodes = {
            "Internet": (1, 9, "blue"), "Router": (2, 7, "blue"),
            "Firewall": (4, 5, "red"), "IoT Hub": (6, 3, "blue"),
            "Device 1": (8, 2, "blue"), "Device 2": (10, 1, "blue"),
            "Device 3": (9, 4, "blue"), "Sinkhole": (5, 8, "black"),
            "Honeypot": (7, 7, "purple")
        }
        for i in range(30):
            self.nodes[f"Dummy {i}"] = (random.uniform(0, 12), random.uniform(0, 12), "#CCCCCC")

        self.edges = [
            ("Internet", "Router"), ("Router", "Firewall"), ("Firewall", "IoT Hub"),
            ("IoT Hub", "Device 1"), ("IoT Hub", "Device 2"), ("IoT Hub", "Device 3"),
            ("Firewall", "Sinkhole"), ("Firewall", "Honeypot")
        ]
        self.events = []
        self.ani = None
        self.reset_animation()

    def _draw_static_network(self):
        self.axes.clear()
        self.axes.set_xlim(0, 12)
        self.axes.set_ylim(0, 12)
        self.axes.set_facecolor('white')
        self.axes.set_xticks([])
        self.axes.set_yticks([])

        for start, end in self.edges:
            if start in self.nodes and end in self.nodes:
                x1, y1, _ = self.nodes[start]
                x2, y2, _ = self.nodes[end]
                self.axes.plot([x1, x2], [y1, y2], '-', color='lightgray', lw=1, zorder=1)

        for name, (x, y, color) in self.nodes.items():
            is_dummy = name.startswith("Dummy")
            size = 5 if is_dummy else 12
            z = 2 if is_dummy else 3
            self.axes.plot(x, y, 'o', markersize=size, color=color, zorder=z)
            if not is_dummy:
                self.axes.text(x, y + 0.4, name, ha='center', fontsize=8, zorder=4)

    def add_packet_route(self, route_nodes: List[str], is_intrusion: bool, attack_type: str, confidence: float):
        path_coords = [self.nodes[n][:2] for n in route_nodes if n in self.nodes]
        if len(path_coords) < 2: return

        smooth_path = []
        for i in range(len(path_coords) - 1):
            x_points = np.linspace(path_coords[i][0], path_coords[i+1][0], 20)
            y_points = np.linspace(path_coords[i][1], path_coords[i+1][1], 20)
            smooth_path.extend(list(zip(x_points, y_points)))

        if not smooth_path: return
        
        color = "red" if is_intrusion else "green"

        self.events.append({'path': smooth_path, 'frame': 0, 'color': color})

        if self.ani and self.ani.event_source and getattr(self.ani.event_source, '_idle', True):
            self.ani.event_source.start()

    def _update_animation(self, frame):
        self._draw_static_network()
        active_events = []
        for event in self.events:
            if event['frame'] < len(event['path']):
                path_so_far = event['path'][:event['frame'] + 1]
                self.axes.plot([p[0] for p in path_so_far], [p[1] for p in path_so_far], lw=2, color=event['color'], zorder=10)
                
                current_pos = event['path'][event['frame']]
                self.axes.plot(current_pos[0], current_pos[1], 'o', markersize=8, color='orange', zorder=11)
                
                event['frame'] += 1
                active_events.append(event)
        
        self.events = active_events
        
        if not self.events and self.ani and self.ani.event_source:
            self.ani.event_source.stop()

    def reset_animation(self):
        if self.ani and self.ani.event_source:
            self.ani.event_source.stop()
        
        self.events.clear()
        
        self.ani = animation.FuncAnimation(self.fig, self._update_animation, blit=False, interval=25, repeat=False, save_count=0)
        self.ani.event_source.stop()
        self._draw_static_network()
        self.draw()

class NetworkTopologyWidget(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout()
        title = QLabel("Network Topology & Routes")
        title.setFont(QFont("Arial", 14, QFont.Bold))
        layout.addWidget(title)
        self.network_canvas = NetworkCanvas(self, width=10, height=8, dpi=100)
        layout.addWidget(self.network_canvas)
        self.setLayout(layout)

    def update_route_visualization(self, route_nodes: List[str], is_intrusion: bool, attack_type: str, confidence: float):
        self.network_canvas.add_packet_route(route_nodes, is_intrusion, attack_type, confidence)

class LogWidget(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout()
        title = QLabel("System Logs")
        title.setFont(QFont("Arial", 14, QFont.Bold))
        layout.addWidget(title)
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setStyleSheet("""
            QTextEdit {
                background-color: #1E1E1E;
                color: #00FF00;
                font-family: 'Courier New';
                font-size: 11px;
                border: 1px solid #333;
                border-radius: 5px;
            }
        """)
        layout.addWidget(self.log_text)
        clear_button = QPushButton("Clear Logs")
        clear_button.clicked.connect(self.clear_logs)
        layout.addWidget(clear_button)
        self.setLayout(layout)
        self.add_log("System initialized", "INFO")

    def add_log(self, message: str, level: str = "INFO"):
        timestamp = datetime.now().strftime("%H:%M:%S")
        color_map = {
            "INFO": "#00FF00",
            "WARNING": "#FFAA00",
            "ERROR": "#FF0000",
            "ATTACK": "#FF00FF",
            "ROUTE": "#00B0FF",
            "VERIFY": "#FFFF00"  # New color for verification
        }
        color = color_map.get(level, "#00FF00")
        log_entry = f'<span style="color: {color}">[{timestamp}] {level}: {message}</span>'
        self.log_text.append(log_entry)
        scrollbar = self.log_text.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())

    def clear_logs(self):
        self.log_text.clear()

class PowerWidget(QWidget):
    def __init__(self, num_devices=5):
        super().__init__()
        self.num_devices = num_devices
        self.power_levels = [100.0] * num_devices
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout()
        title = QLabel("Simulated IoT Device Power")
        title.setFont(QFont("Arial", 14, QFont.Bold))
        layout.addWidget(title)
        self.progress_bars = []
        grid_layout = QGridLayout()
        for i in range(self.num_devices):
            label = QLabel(f"Device {i+1}:")
            progress = QProgressBar()
            progress.setRange(0, 100)
            progress.setValue(100)
            progress.setStyleSheet("""
                QProgressBar {
                    border: 1px solid grey;
                    border-radius: 5px;
                    text-align: center;
                }
                QProgressBar::chunk {
                    background-color: #4CAF50;
                }
            """)
            grid_layout.addWidget(label, i, 0)
            grid_layout.addWidget(progress, i, 1)
            self.progress_bars.append(progress)
        layout.addLayout(grid_layout)
        layout.addStretch()
        self.setLayout(layout)

    def update_power(self, device_index: int, new_level: float):
        if 0 <= device_index < self.num_devices:
            self.power_levels[device_index] = new_level
            self.progress_bars[device_index].setValue(int(new_level))
            if new_level < 20:
                self.progress_bars[device_index].setStyleSheet("QProgressBar::chunk { background-color: #F44336; }")
            elif new_level < 50:
                self.progress_bars[device_index].setStyleSheet("QProgressBar::chunk { background-color: #FFC107; }")
            else:
                self.progress_bars[device_index].setStyleSheet("QProgressBar::chunk { background-color: #4CAF50; }")

class StatisticsWidget(QWidget):
    def __init__(self):
        super().__init__()
        self.setup_ui()
        self.attack_counts = {}
        self.proc_times = []
        self.last_time = time.time()
        self.total_packets = 0

    def setup_ui(self):
        layout = QVBoxLayout()
        attack_group = QGroupBox("Predicted Attack Type Counts")
        attack_layout = QGridLayout()
        self.attack_labels = {}
        self._attack_layout = attack_layout
        self._attack_row = 0
        attack_group.setLayout(attack_layout)
        layout.addWidget(attack_group)
        perf_group = QGroupBox("Performance Metrics")
        perf_layout = QGridLayout()
        self.processing_time_label = QLabel("0.00 ms")
        self.throughput_label = QLabel("0.0 pps")
        perf_layout.addWidget(QLabel("Avg Processing Time:"), 0, 0)
        perf_layout.addWidget(self.processing_time_label, 0, 1)
        perf_layout.addWidget(QLabel("Throughput:"), 1, 0)
        perf_layout.addWidget(self.throughput_label, 1, 1)
        perf_group.setLayout(perf_layout)
        layout.addWidget(perf_group)
        layout.addStretch()
        self.setLayout(layout)

    def _ensure_attack_label(self, attack_type: str):
        if attack_type not in self.attack_labels:
            label_name = QLabel(f"{attack_type}:")
            count_label = QLabel("0")
            count_label.setStyleSheet("font-weight: bold; color: #D32F2F;")
            self._attack_layout.addWidget(label_name, self._attack_row, 0)
            self._attack_layout.addWidget(count_label, self._attack_row, 1)
            self._attack_row += 1
            self.attack_labels[attack_type] = count_label

    def update_statistics(self, prediction_result: Dict):
        self.total_packets += 1
        atype = prediction_result.get('predicted_attack_type', 'Normal')
        self._ensure_attack_label(atype)
        self.attack_counts[atype] = self.attack_counts.get(atype, 0) + 1
        self.attack_labels[atype].setText(str(self.attack_counts[atype]))
        self.proc_times.append(float(prediction_result.get('processing_time_ms', 0.0)))
        if len(self.proc_times) > 200:
            self.proc_times = self.proc_times[-200:]
        avg_proc = np.mean(self.proc_times) if self.proc_times else 0.0
        self.processing_time_label.setText(f"{avg_proc:.2f} ms")
        now = time.time()
        elapsed = max(1e-6, now - self.last_time)
        pps = 1.0 / elapsed
        self.throughput_label.setText(f"{pps:.1f} pps")
        self.last_time = now

class PowerSimulator:
    def __init__(self, num_devices=5, power_update_callback=None):
        self.num_devices = num_devices
        self.power_levels = np.array([100.0] * num_devices, dtype=float)
        self.base_drain_rate = 0.001
        self.tx_cost = 0.05
        self.last_update_time = time.time()
        self.callback = power_update_callback

    def simulate_drain(self):
        now = time.time()
        elapsed = now - self.last_update_time
        if elapsed < 1.0:
            return
        self.power_levels -= self.base_drain_rate * elapsed
        if random.random() < 0.2:
            device_idx = random.randint(0, self.num_devices - 1)
            self.power_levels[device_idx] -= self.tx_cost
        self.power_levels = np.clip(self.power_levels, 0, 100)
        self.last_update_time = now
        if self.callback:
            for i in range(self.num_devices):
                self.callback(i, self.power_levels[i])

# ========================= Main Window =========================
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.worker = None
        self.setup_ui()
        self.route_manager = RouteManager(self.log_widget.add_log)
        self.power_simulator = PowerSimulator(power_update_callback=self.power_widget.update_power)
        self.setup_style()
        self.config_widget.source_combo.currentIndexChanged.connect(self.on_source_changed)
        self.config_widget.refresh_interfaces_button.clicked.connect(self.refresh_interfaces)
        self.config_widget.browse_pcap_button.clicked.connect(self.browse_for_pcap)
        self.refresh_interfaces()
        self.on_source_changed()
        # Timer to read events from NS-3
        self.event_timer = QTimer()
        self.event_timer.timeout.connect(self.read_ns3_events)
        self.event_timer.start(1000)  # Check every 1 second

    def browse_for_pcap(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Open PCAP File", "", "PCAP Files (*.pcap *.pcapng)")
        if file_path:
            self.config_widget.pcap_file_path_label.setText(os.path.basename(file_path))
            self.pcap_file_path = file_path
        else:
            self.config_widget.pcap_file_path_label.setText("No file selected.")
            self.pcap_file_path = None

    def refresh_interfaces(self):
        self.config_widget.interface_combo.clear()
        try:
            interfaces = get_if_list()
            self.config_widget.interface_combo.addItems(interfaces)
        except Exception as e:
            self.log_widget.add_log(f"Could not list network interfaces: {e}", "ERROR")

    def on_source_changed(self):
        source = self.config_widget.source_combo.currentText()
        is_simulator = (source == "Simulator")
        is_live = (source == "Live Capture")
        is_pcap = (source == "PCAP File")
        self.config_widget.simulator_group.setVisible(is_simulator)
        self.config_widget.interface_label.setVisible(is_live)
        self.config_widget.interface_combo.setVisible(is_live)
        self.config_widget.refresh_interfaces_button.setVisible(is_live)
        self.config_widget.pcap_file_label.setVisible(is_pcap)
        self.config_widget.pcap_file_path_label.setVisible(is_pcap)
        self.config_widget.browse_pcap_button.setVisible(is_pcap)

    def setup_ui(self):
        self.setWindowTitle("Network Intrusion Detection System (NIDS) - 6-Feature Bot-IoT")
        self.setGeometry(100, 100, 1500, 950)
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout()
        header_layout = QHBoxLayout()
        title = QLabel("NIDS Dashboard - 6-Feature Bot-IoT Model")
        title.setFont(QFont("Arial", 20, QFont.Bold))
        title.setStyleSheet("color: #1A237E; margin: 10px;")
        header_layout.addWidget(title)
        header_layout.addStretch()
        self.start_button = QPushButton("Start Monitoring")
        self.start_button.clicked.connect(self.start_monitoring)
        self.start_button.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50;
                color: white;
                border: none;
                padding: 10px 20px;
                border-radius: 5px;
                font-size: 14px;
                font-weight: bold;
            }
            QPushButton:hover { background-color: #45a049; }
        """)
        self.stop_button = QPushButton("Stop Monitoring")
        self.stop_button.clicked.connect(self.stop_monitoring)
        self.stop_button.setEnabled(False)
        self.stop_button.setStyleSheet("""
            QPushButton {
                background-color: #F44336;
                color: white;
                border: none;
                padding: 10px 20px;
                border-radius: 5px;
                font-size: 14px;
                font-weight: bold;
            }
            QPushButton:hover { background-color: #da190b; }
            QPushButton:disabled { background-color: #CCCCCC; }
        """)
        header_layout.addWidget(self.start_button)
        header_layout.addWidget(self.stop_button)
        main_layout.addLayout(header_layout)
        self.status_label = QLabel("System Ready - 6-Feature Model")
        self.status_label.setStyleSheet("color: #666; margin: 5px; font-size: 12px;")
        main_layout.addWidget(self.status_label)
        self.tab_widget = QTabWidget()
        dashboard_tab = QWidget()
        dashboard_layout = QVBoxLayout()
        self.metrics_widget = MetricsWidget()
        dashboard_layout.addWidget(self.metrics_widget)
        splitter = QSplitter(Qt.Horizontal)
        self.traffic_viz = TrafficVisualizationWidget()
        splitter.addWidget(self.traffic_viz)
        self.alert_widget = AlertWidget()
        splitter.addWidget(self.alert_widget)
        splitter.setSizes([800, 500])
        dashboard_layout.addWidget(splitter)
        dashboard_tab.setLayout(dashboard_layout)
        self.tab_widget.addTab(dashboard_tab, "Dashboard")
        self.config_widget = ConfigurationWidget()
        self.tab_widget.addTab(self.config_widget, "Configuration")
        self.topology_widget = NetworkTopologyWidget()
        self.tab_widget.addTab(self.topology_widget, "Network Topology")
        self.routes_widget = RoutesWidget()
        self.tab_widget.addTab(self.routes_widget, "Routes")
        self.stats_widget = StatisticsWidget()
        self.tab_widget.addTab(self.stats_widget, "Statistics")
        self.log_widget = LogWidget()
        self.tab_widget.addTab(self.log_widget, "Logs")
        self.power_widget = PowerWidget()
        self.tab_widget.addTab(self.power_widget, "Power")
        main_layout.addWidget(self.tab_widget)
        central_widget.setLayout(main_layout)
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.update_status)
        self.update_timer.start(1000)
        self.power_timer = QTimer()
        self.power_timer.timeout.connect(self.update_power_simulation)
        self.power_timer.start(1000)

    def update_power_simulation(self):
        self.power_simulator.simulate_drain()

    def setup_style(self):
        self.setStyleSheet("""
            QMainWindow { background-color: #F5F5F5; }
            QTabWidget::pane { border: 1px solid #C0C0C0; background-color: white; }
            QTabBar::tab { background-color: #E0E0E0; padding: 10px 20px; margin-right: 2px; }
            QTabBar::tab:selected { background-color: white; border-bottom: 2px solid #2196F3; }
            QGroupBox { font-weight: bold; border: 2px solid #CCCCCC; border-radius: 5px; margin: 10px; padding-top: 10px; }
            QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 10px 0 10px; }
        """)

    def start_monitoring(self):
        if self.worker is None:
            self.metrics_widget.reset_metrics()
            self.log_widget.clear_logs()
            self.alert_widget.alert_table.setRowCount(0)
            self.routes_widget.routes_table.setRowCount(0)
            self.stats_widget.attack_counts = {}
            self.topology_widget.network_canvas.reset_animation()
            # Clear attack labels
            for i in reversed(range(self.stats_widget._attack_layout.count())):
                w = self.stats_widget._attack_layout.itemAt(i).widget()
                if w:
                    w.setParent(None)
            self.stats_widget.attack_labels = {}
            self.stats_widget._attack_row = 0
            self.worker = NetworkTrafficWorker()
            self.worker.packet_received.connect(self.on_packet_received)
            self.worker.prediction_made.connect(self.on_prediction_made)
            self.worker.source = self.config_widget.source_combo.currentText()
            if self.worker.source == "Simulator":
                self.worker.traffic_simulator.packet_rate = self.config_widget.packet_rate_spin.value()
                self.worker.traffic_simulator.attack_probability = self.config_widget.attack_prob_spin.value() / 100.0
            elif self.worker.source == "Live Capture":
                self.worker.interface = self.config_widget.interface_combo.currentText()
                if not self.worker.interface:
                    self.log_widget.add_log("No network interface selected for live capture.", "ERROR")
                    self.worker = None
                    return
            elif self.worker.source == "PCAP File":
                if hasattr(self, 'pcap_file_path') and self.pcap_file_path:
                    self.worker.pcap_file = self.pcap_file_path
                else:
                    self.log_widget.add_log("No PCAP file selected.", "ERROR")
                    self.worker = None
                    return
            self.worker.detection_threshold = self.config_widget.threshold_spin.value() / 100.0
            self.worker.start()
            self.start_button.setEnabled(False)
            self.stop_button.setEnabled(True)
            self.status_label.setText("Monitoring Active - 6-Feature Model")
            self.status_label.setStyleSheet("color: #4CAF50; margin: 5px; font-size: 12px; font-weight: bold;")
            self.log_widget.add_log("Monitoring started (6-feature Bot-IoT model)", "INFO")

    def stop_monitoring(self):
        if self.worker:
            self.worker.stop()
            self.worker = None
            self.start_button.setEnabled(True)
            self.stop_button.setEnabled(False)
            self.status_label.setText("Monitoring Stopped")
            self.status_label.setStyleSheet("color: #F44336; margin: 5px; font-size: 12px; font-weight: bold;")
            self.log_widget.add_log("Monitoring stopped", "INFO")

    def on_packet_received(self, packet: Dict):
        pass

    def compute_route(self, prediction_result: Dict) -> Tuple[List[str], str]:
        auto_block = self.config_widget.auto_block_check.isChecked()
        reroute_mode = self.config_widget.reroute_mode_combo.currentText()
        info = prediction_result['packet_info']
        is_intrusion = prediction_result['is_intrusion']
        atype = prediction_result.get('predicted_attack_type', 'Attack')
        device_index = (info.get('dst_ip_int', 0) % 3) + 1
        device_name = f"Device {device_index}"
        normal_route = ["Internet", "Router", "Firewall", "IoT Hub", device_name]
        if not is_intrusion:
            return normal_route, "Forward"
        if not auto_block or reroute_mode == "Forward Only":
            return normal_route, "Forward (Alert Only)"
        if reroute_mode == "Smart":
            if atype == 'Reconnaissance':
                return ["Internet", "Router", "Firewall", "Honeypot"], "Rerouted to Honeypot"
            else:
                return ["Internet", "Router", "Firewall", "Sinkhole"], "Rerouted to Sinkhole"
        elif reroute_mode == "Sinkhole":
            return ["Internet", "Router", "Firewall", "Sinkhole"], "Rerouted to Sinkhole"
        elif reroute_mode == "Honeypot":
            return ["Internet", "Router", "Firewall", "Honeypot"], "Rerouted to Honeypot"
        elif reroute_mode == "Drop":
            src_ip_to_block = prediction_result['packet_info'].get('src_ip_str')
            if src_ip_to_block:
                self.route_manager.block_ip(src_ip_to_block)
            return ["Internet", "Router", "Firewall"], "Dropped"
        return normal_route, "Forward (Alert Only)"

    def on_prediction_made(self, prediction_result: Dict):
        self.metrics_widget.update_metrics(prediction_result)
        self.traffic_viz.update_plots(prediction_result)
        route_nodes, action = self.compute_route(prediction_result)
        self.topology_widget.update_route_visualization(
            route_nodes,
            prediction_result['is_intrusion'],
            prediction_result.get('predicted_attack_type', prediction_result['predicted_class']),
            prediction_result['confidence']
        )
        # Write command to file for NS-3
        command = {
            "timestamp": prediction_result['timestamp'].isoformat(),
            "src_ip": prediction_result['packet_info']['src_ip_str'],
            "dst_ip": prediction_result['packet_info']['dst_ip_str'],
            "sport": prediction_result['packet_info']['sport'],
            "dport": prediction_result['packet_info']['dport'],
            "attack_type": prediction_result.get('predicted_attack_type', 'Attack'),
            "is_intrusion": prediction_result['is_intrusion'],
            "action": action,
            "route": route_nodes
        }
        try:
            with open(COMMAND_FILE, 'w') as f:
                json.dump(command, f)
            self.log_widget.add_log(f"Command written to {COMMAND_FILE}: {action}", "INFO")
        except Exception as e:
            self.log_widget.add_log(f"Failed to write command: {e}", "ERROR")
        # Add route with empty verification initially
        self.routes_widget.add_route(prediction_result, route_nodes, action)
        # ALWAYS add to alerts (both Normal and Attack)
        self.alert_widget.add_alert(prediction_result, action)
        if prediction_result['is_intrusion']:
            # GUI Log Message
            msg = (f"INTRUSION: {prediction_result.get('predicted_attack_type','Attack')} | "
                   f"Conf={prediction_result['confidence']:.3f} | "
                   f"Route={ ' → '.join(route_nodes) } | Action={action}")
            self.log_widget.add_log(msg, "ATTACK")

            # Formatted Console Log (as per user request for every detail)
            print("\n=============================================")
            print("  INTRUSION DETECTED")
            print("=============================================")
            print(f"  Timestamp:       {prediction_result['timestamp'].strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"  Attack Type:     {prediction_result.get('predicted_attack_type', 'Attack')}")
            print(f"  Confidence:      {prediction_result['confidence']:.3f}")
            print(f"  Source IP:       {prediction_result['packet_info']['src_ip_str']}")
            print(f"  Destination IP:  {prediction_result['packet_info']['dst_ip_str']}")
            print(f"  Source Port:     {prediction_result['packet_info']['sport']}")
            print(f"  Destination Port:{prediction_result['packet_info']['dport']}")
            print(f"  Action Taken:    {action}")
            print(f"  Rerouted Path:   {' → '.join(route_nodes)}")
            print("=============================================\n")

        else:
            if self.metrics_widget.total_packets % 50 == 0:
                # Also print these less-frequent info logs to the console
                info_msg = f"Processed {self.metrics_widget.total_packets} packets"
                self.log_widget.add_log(info_msg, "INFO")
                print(f"[{datetime.now().strftime('%H:%M:%S')}] [INFO] {info_msg}")
        self.stats_widget.update_statistics(prediction_result)

    def read_ns3_events(self):
        """Read events from NS-3 and update UI."""
        if not os.path.exists(EVENT_FILE):
            return
        try:
            with open(EVENT_FILE, 'r') as f:
                events = json.load(f)
            # Clear the file after reading
            open(EVENT_FILE, 'w').close()
            for event in events:
                etype = event.get('type', '')
                msg = event.get('message', '')
                if etype == 'verification':
                    self.log_widget.add_log(f"Verification: {msg}", "VERIFY")
                elif etype == 'reroute':
                    self.log_widget.add_log(f"Reroute: {msg}", "ROUTE")
        except Exception as e:
            self.log_widget.add_log(f"Error reading events: {e}", "ERROR")

    def update_status(self):
        if self.worker and self.worker.is_running:
            current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            packets_processed = self.metrics_widget.total_packets
            self.status_label.setText(f"Active - {current_time} | Packets: {packets_processed}")

    def closeEvent(self, event):
        if self.worker:
            self.worker.stop()
        self.route_manager.cleanup()
        # Cleanup command and event files
        for f in [COMMAND_FILE, EVENT_FILE]:
            if os.path.exists(f):
                try:
                    os.remove(f)
                except:
                    pass
        event.accept()

# ========================= Main Entry Point =========================
def main():
    app = QApplication(sys.argv)
    app.setApplicationName("Bot-IoT Aligned NIDS (6-feature)")
    app.setApplicationVersion("4.2")
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()