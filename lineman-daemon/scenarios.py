"""
scenarios.py — Ghost-Protocol Security Scenarios
================================================
Implements functional security research logic for offensive/defensive scenarios.
These are used to verify HIPS effectiveness and trigger SOC alerts.
"""

import logging
import socket
import threading
import time
import random
import os

log = logging.getLogger(__name__)

# ── Scenario s1: Trojan-Egress ───────────────────────────────────────────────

def run_s1_trojan_egress(target_ip: str = "127.0.0.1", port: int = 443):
    """
    Simulates a multi-stage exfiltration by attempting to send data 
    over a connection with spoofed SNI/Host headers.
    """
    def _exfiltrate():
        log.info("[scenario-s1] Initiating Trojan-Egress exfiltration to %s:%d", target_ip, port)
        try:
            # Stage 1: Handshake with a "legitimate" looking SNI
            # In a real scenario, this would be a raw socket manipulation.
            # Here we simulate the network behavior that Lineman's forensics would see.
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((target_ip, port))
            
            # Simulated TLS ClientHello with SNI 'metrics.apple.com' (Classified as APPLE_SERVICES)
            # This tests if the forensic engine correctly identifies the spoofed host.
            fake_sni_payload = b"\x16\x03\x01\x00\x8d\x01\x00\x00\x89\x03\x03" + os.urandom(32) + b"\x00\x00\x02\x00\x00\x00\x00\x00\x12\x00\x10\x00\x00\x0dmetrics.apple.com"
            sock.sendall(fake_sni_payload)
            
            time.sleep(1)
            sock.close()
            log.info("[scenario-s1] Trojan-Egress simulation complete.")
        except Exception as e:
            log.error("[scenario-s1] Simulation failed: %s", e)

    threading.Thread(target=_exfiltrate, daemon=True).start()


# ── Scenario s2: Side-Channel-Leak ───────────────────────────────────────────

def run_s2_side_channel_leak(target_ip: str = "127.0.0.1", port: int = 80):
    """
    Simulates data leakage via packet timing and size modulation (steganography).
    """
    def _leak():
        log.info("[scenario-s2] Initiating Side-Channel-Leak modulation.")
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            secret_data = "GHOST_PROTOCOL_REVEALED"
            for char in secret_data:
                # Modulate packet size based on ASCII value
                size = ord(char) + 100
                payload = os.urandom(size)
                sock.sendto(payload, (target_ip, port))
                
                # Modulate timing
                time.sleep(random.uniform(0.1, 0.5))
                
            sock.close()
            log.info("[scenario-s2] Side-Channel-Leak simulation complete.")
        except Exception as e:
            log.error("[scenario-s2] Simulation failed: %s", e)

    threading.Thread(target=_leak, daemon=True).start()


# ── Scenario s3: Buffer-Overflow-Sim ─────────────────────────────────────────

def run_s3_buffer_overflow_sim(target_ip: str = "127.0.0.1", port: int = 8080):
    """
    Injects a large, crafted payload to test buffer handling and trigger 
    integrity/overflow alerts in the SOC.
    """
    def _overflow():
        log.info("[scenario-s3] Initiating Buffer-Overflow crafted payload injection.")
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((target_ip, port))
            
            # Crafted payload: NOP sled + shellcode placeholder + overflow padding
            payload = b"\x90" * 1024 + b"SHELLCODE_PLACEHOLDER" + b"A" * 4096
            sock.sendall(payload)
            
            sock.close()
            log.info("[scenario-s3] Buffer-Overflow simulation complete.")
        except Exception as e:
            log.error("[scenario-s3] Simulation failed: %s", e)

    threading.Thread(target=_overflow, daemon=True).start()
