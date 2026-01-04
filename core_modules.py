import threading
import time
import subprocess
import socket
import datetime
import sys
import json
import os
import hmac
import hashlib

try:
    from scapy.all import sniff, IP, IPv6, TCP, UDP, ARP, Raw
except ImportError:
    pass

class FirewallManager:
    @staticmethod
    def block_ip(ip_address):
        rule_name = f"HIPS_BLOCK_{ip_address}"
        command = f"netsh advfirewall firewall add rule name=\"{rule_name}\" dir=in action=block remoteip={ip_address}"
        try:
            subprocess.run(command, shell=True, check=True, stdout=subprocess.DEVNULL)
            print(f"[FIREWALL] Blocked IP: {ip_address}")
            return True
        except:
            print(f"[ERROR] Failed to block {ip_address}")
            return False

    @staticmethod
    def unblock_ip(ip_address):
        rule_name = f"HIPS_BLOCK_{ip_address}"
        command = f'netsh advfirewall firewall delete rule name="{rule_name}"'
        try:
            subprocess.run(command, shell=True, check=True, stdout=subprocess.DEVNULL)
            print(f"[FIREWALL] Unblocked IP: {ip_address}")
            return True
        except:
            print(f"[ERROR] Failed to unblock {ip_address}")
            return False

class PacketCaptureThread(threading.Thread):
    def __init__(self, packet_queue):
        super().__init__()
        self.packet_queue = packet_queue
        self.stop_event = threading.Event()
        self.daemon = True

    def run(self):
        print("[SNIFFER] Started...")
        while not self.stop_event.is_set():
            try:
                sniff(count=1, prn=self.process_packet, store=0, timeout=1)
            except:
                time.sleep(1)

    def process_packet(self, packet):
        if IP in packet or ARP in packet:
            self.packet_queue.put(packet)

    def stop(self):
        self.stop_event.set()

class DetectionEngine(threading.Thread):
    def __init__(self, packet_queue, gui_callback, blacklist_bst, alert_stack, analyze_local=False):
        super().__init__()
        self.packet_queue = packet_queue
        self.stop_event = threading.Event()
        self.daemon = True
        self.gui_callback = gui_callback
        self.blacklist = blacklist_bst
        self.alert_stack = alert_stack
        self.analyze_local = analyze_local
        
        self.packet_counts = {} 
        self.port_map = {} 
        self.syn_track = {} 
        self.blocked_ips = set() 
        self.blocked_lock = threading.Lock()
        self.start_time = time.time()
        
        self.arp_table = {}
        self.whitelist = set()
        self.local_ip = "127.0.0.1" # Simplified

    def run(self):
        print("[DETECTION] Engine Started...")
        while not self.stop_event.is_set():
            try:
                if not self.packet_queue.empty():
                    pkt = self.packet_queue.get()
                    self.analyze(pkt)
                else:
                    time.sleep(0.1)
            except:
                pass

    def analyze(self, pkt):
        if IP in pkt:
            src = pkt[IP].src
            dst = pkt[IP].dst
            
            # Traffic Logging
            if src not in self.blocked_ips:
                self.gui_callback("TRAFFIC", (src, src, dst, "IP", len(pkt)))

            # DOS Detection Logic (Example)
            self.packet_counts[src] = self.packet_counts.get(src, 0) + 1
            
            if self.packet_counts[src] > 100 and src not in self.blocked_ips:
                with self.blocked_lock:
                    if src not in self.blocked_ips:
                        self.blocked_ips.add(src)
                        self.blacklist.insert(src)
                        FirewallManager.block_ip(src)
                        
                        # Push to Stack
                        self.alert_stack.push(f"High Traffic from {src}")
                        
                        # Notify GUI
                        self.gui_callback("ALERT", (src, "High Traffic/DOS", "High"))

    def unblock_ip(self, ip):
        with self.blocked_lock:
            if ip in self.blocked_ips:
                self.blocked_ips.remove(ip)
            self.blacklist.delete(ip)
        FirewallManager.unblock_ip(ip)

    def stop(self):
        self.stop_event.set()
