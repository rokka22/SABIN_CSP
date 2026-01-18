"""
Network Scanner Module
Discovers active hosts on the local network using ARP scanning
"""

import subprocess
import re
from datetime import datetime
import json
import os

class NetworkScanner:
    def __init__(self):
        self.devices = []
        self.scan_timestamp = None
    
    def scan_network(self, ip_range="192.168.1.0/24"):
        """
        Scan network for active devices using ARP
        ip_range: Network range to scan (default: 192.168.1.0/24)
        """
        print(f"[*] Starting network scan on {ip_range}...")
        self.scan_timestamp = datetime.now()
        
        try:
            # Simple ping scan to discover hosts
            result = subprocess.run(
                f"arp -a",
                capture_output=True,
                text=True,
                shell=True
            )
            
            self.parse_arp_output(result.stdout)
            print(f"[+] Found {len(self.devices)} devices")
            return self.devices
            
        except Exception as e:
            print(f"[-] Error during scan: {e}")
            return []
    
    def parse_arp_output(self, arp_output):
        """Parse ARP table output"""
        self.devices = []
        lines = arp_output.strip().split('\n')
        
        for line in lines:
            # Match lines with IP and MAC addresses
            match = re.search(r'(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f]{2}(?::[0-9a-f]{2}){5})', line, re.IGNORECASE)
            if match:
                ip = match.group(1)
                mac = match.group(2)
                
                device = {
                    'ip': ip,
                    'mac': mac,
                    'hostname': self.get_hostname(ip),
                    'ports': [],
                    'os': 'Unknown',
                    'timestamp': self.scan_timestamp.isoformat()
                }
                self.devices.append(device)
    
    def get_hostname(self, ip):
        """Get hostname from IP (simplified)"""
        try:
            result = subprocess.run(
                f"nslookup {ip}",
                capture_output=True,
                text=True,
                shell=True,
                timeout=2
            )
            match = re.search(r'Name:\s+([^\s]+)', result.stdout)
            if match:
                return match.group(1)
        except:
            pass
        return ip
    
    def save_results(self, filename="scan_results.json"):
        """Save scan results to JSON file"""
        with open(filename, 'w') as f:
            json.dump(self.devices, f, indent=2)
        print(f"[+] Results saved to {filename}")
    
    def get_device_summary(self):
        """Get summary of scanned devices"""
        return {
            'total_devices': len(self.devices),
            'scan_time': self.scan_timestamp.isoformat() if self.scan_timestamp else None,
            'devices': self.devices
        }


if __name__ == "__main__":
    scanner = NetworkScanner()
    devices = scanner.scan_network()
    
    print("\n[+] Active Devices Found:")
    for device in devices:
        print(f"  IP: {device['ip']:15} | MAC: {device['mac']:17} | Hostname: {device['hostname']}")
    
    scanner.save_results()
