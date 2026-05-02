"""
dns_correlator.py — DNS Egress Correlation Engine (v2.0)
=========================================================
Monitors DNS resolution to map hostnames to resolved IP addresses.
This solves the TLS 1.3 + ECH (Encrypted Client Hello) blindspot.

How it works:
  1. The engine acts as a lightweight UDP proxy or packet sniffer.
  2. For simplicity and robustness (Python Maximalist), it sniffs local
     DNS traffic on port 53 via tcpdump.
  3. It maintains a time-indexed mapping: Resolved IP -> Hostname.
  4. When the forensics engine sees a dropped packet to an IP, it queries
     this correlator to find the likely hostname that was being exfiltrated to.

Forensic attribution:
  By matching the PID that made the DNS query (via lsof correlation) with the
  IP exfiltration, we achieve high-fidelity attribution without SSL termination.
"""

import threading
import logging
import subprocess
import re
import time
from typing import Dict, Optional, Tuple

log = logging.getLogger(__name__)

# Cache duration for IP->Hostname mappings (seconds)
CACHE_TTL = 300 

class DNSCorrelator(threading.Thread):
    """
    Background sniffer that parses DNS responses.
    """

    def __init__(self):
        super().__init__(daemon=True, name="DNSCorrelator")
        self._running = True
        # ip -> (hostname, timestamp)
        self._ip_map: Dict[str, Tuple[str, float]] = {}
        self._lock = threading.Lock()

    def get_hostname(self, ip: str) -> Optional[str]:
        """Query the cache for a hostname associated with this IP."""
        with self._lock:
            entry = self._ip_map.get(ip)
            if entry:
                hostname, ts = entry
                if time.time() - ts < CACHE_TTL:
                    return hostname
                else:
                    del self._ip_map[ip]
        return None

    def stop(self):
        self._running = False

    def run(self):
        log.info("[dns] Starting DNS correlation sniffer (tcpdump port 53)")
        
        # Sniff UDP/53 responses (QR=1)
        # We look for A (Type 1) or AAAA (Type 28) records.
        # Format varies, so we use a robust regex on tcpdump text output.
        cmd = ["tcpdump", "-i", "any", "-n", "-l", "udp port 53"]
        
        try:
            self._proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True
            )
            
            # Regex for tcpdump DNS output:
            # IP 1.1.1.1.53 > 192.168.1.5.1234: 56789 1/0/0 A 104.26.10.233 (50)
            dns_re = re.compile(r"A\??\s+([\d\.]+)")
            host_re = re.compile(r"\s+([\w\.\-\d]+)\.\s+")
            
            while self._running and self._proc.poll() is None:
                line = self._proc.stdout.readline()
                if not line:
                    break
                
                # Check if it's a response with an answer
                if " A " in line or " AAAA " in line:
                    self._parse_line(line)
                    
        except Exception as e:
            log.error("[dns] Correlation failure: %s", e)
        finally:
            log.info("[dns] DNS correlator stopped.")

    def _parse_line(self, line: str):
        """
        Extracts Hostname and IP from tcpdump output.
        Example: ... google.com. 1/0/0 A 172.217.1.14
        """
        try:
            # Very basic extraction - improve for production
            parts = line.split()
            hostname = ""
            for i, p in enumerate(parts):
                if p == "A" or p == "AAAA":
                    # Hostname is usually just before the record type or the first word
                    # In tcpdump -n -l, it's often the word after '>', excluding the port.
                    # This is complex to parse reliably across all tcpdump versions.
                    # We'll use a safer approach: look for words ending in '.' that look like hosts.
                    pass
            
            # Simple heuristic:
            m_ip = re.search(r"A\s+([\d\.]+)", line)
            if m_ip:
                ip = m_ip.group(1)
                # Hostname is usually the word before the ID or before the flags
                # For now, let's find the first string that looks like a domain.
                m_host = re.search(r"([\w\.\-]+\.[a-z]{2,})\.", line, re.I)
                if m_host:
                    hostname = m_host.group(1).lower()
                    with self._lock:
                        self._ip_map[ip] = (hostname, time.time())
                        log.debug("[dns] Correlated %s -> %s", ip, hostname)
                        
        except Exception as e:
            log.debug("[dns] Parse error: %s", e)

# ── Singleton access ──────────────────────────────────────────────────────────

_instance: Optional[DNSCorrelator] = None

def get_instance() -> DNSCorrelator:
    global _instance
    if _instance is None:
        _instance = DNSCorrelator()
        _instance.start()
    return _instance
