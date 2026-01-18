"""
Anomaly Detection Module
Identifies suspicious network activity and threats
"""

from datetime import datetime
from collections import defaultdict
import json

class AnomalyDetector:
    def __init__(self):
        self.alerts = []
        self.suspicious_ips = set()
        self.threshold_settings = {
            'high_port_count': 50,      # Ports scanned
            'syn_flood_threshold': 100,  # SYN packets
            'bandwidth_threshold': 100,  # MB
            'arp_broadcast_threshold': 50
        }
    
    def detect_anomalies(self, packets_list, ip_stats=None):
        """
        Detect anomalies in network traffic
        packets_list: List of captured packets
        ip_stats: IP statistics from packet analyzer
        """
        print("[*] Starting anomaly detection...")
        self.alerts = []
        self.suspicious_ips = set()
        
        if packets_list:
            self._detect_port_scanning(packets_list)
            self._detect_syn_flood(packets_list)
            self._detect_arp_spoofing(packets_list)
            self._detect_bandwidth_abuse(ip_stats)
            self._detect_unusual_ports(packets_list)
        
        print(f"[+] Detection complete. Found {len(self.alerts)} alerts")
        return self.alerts
    
    def _detect_port_scanning(self, packets):
        """Detect port scanning activity"""
        port_activity = defaultdict(set)
        
        for packet in packets:
            src_ip = packet.get('src_ip')
            dst_port = packet.get('dst_port')
            
            if src_ip and dst_port:
                port_activity[src_ip].add(dst_port)
        
        for src_ip, ports in port_activity.items():
            if len(ports) > self.threshold_settings['high_port_count']:
                self._create_alert(
                    'PORT_SCAN',
                    src_ip,
                    f'Scanning {len(ports)} different ports - Possible port scanner',
                    'HIGH'
                )
                self.suspicious_ips.add(src_ip)
    
    def _detect_syn_flood(self, packets):
        """Detect SYN flood attacks"""
        syn_count = defaultdict(int)
        
        for packet in packets:
            if 'S' in packet.get('flags', ''):  # SYN flag
                src_ip = packet.get('src_ip')
                if src_ip:
                    syn_count[src_ip] += 1
        
        for src_ip, count in syn_count.items():
            if count > self.threshold_settings['syn_flood_threshold']:
                self._create_alert(
                    'SYN_FLOOD',
                    src_ip,
                    f'{count} SYN packets detected - Possible DDoS attack',
                    'CRITICAL'
                )
                self.suspicious_ips.add(src_ip)
    
    def _detect_arp_spoofing(self, packets):
        """Detect ARP spoofing attempts"""
        arp_activity = defaultdict(int)
        
        for packet in packets:
            if packet.get('protocol') == 'ARP':
                src_ip = packet.get('src_ip')
                if src_ip:
                    arp_activity[src_ip] += 1
        
        for src_ip, count in arp_activity.items():
            if count > self.threshold_settings['arp_broadcast_threshold']:
                self._create_alert(
                    'ARP_SPOOFING',
                    src_ip,
                    f'{count} ARP packets from single source - Possible ARP spoofing',
                    'MEDIUM'
                )
                self.suspicious_ips.add(src_ip)
    
    def _detect_bandwidth_abuse(self, ip_stats):
        """Detect excessive bandwidth usage"""
        if not ip_stats:
            return
        
        for ip, stats in ip_stats.items():
            bytes_sent = stats.get('bytes', 0)
            mb_sent = bytes_sent / (1024 * 1024)
            
            if mb_sent > self.threshold_settings['bandwidth_threshold']:
                self._create_alert(
                    'HIGH_BANDWIDTH',
                    ip,
                    f'{mb_sent:.2f} MB transferred - Possible data exfiltration',
                    'MEDIUM'
                )
                self.suspicious_ips.add(ip)
    
    def _detect_unusual_ports(self, packets):
        """Detect connections to unusual ports"""
        suspicious_ports = {23, 135, 139, 445, 21}  # Common attack ports
        port_activity = defaultdict(set)
        
        for packet in packets:
            src_ip = packet.get('src_ip')
            dst_port = packet.get('dst_port')
            
            if src_ip and dst_port in suspicious_ports:
                port_activity[src_ip].add(dst_port)
        
        for src_ip, ports in port_activity.items():
            for port in ports:
                self._create_alert(
                    'SUSPICIOUS_PORT',
                    src_ip,
                    f'Connection to port {port} - Potentially dangerous',
                    'LOW'
                )
    
    def _create_alert(self, alert_type, source_ip, description, severity):
        """Create an alert"""
        alert = {
            'timestamp': datetime.now().isoformat(),
            'type': alert_type,
            'source_ip': source_ip,
            'description': description,
            'severity': severity
        }
        self.alerts.append(alert)
    
    def get_critical_alerts(self):
        """Get only critical alerts"""
        return [a for a in self.alerts if a['severity'] == 'CRITICAL']
    
    def get_alerts_by_severity(self):
        """Group alerts by severity"""
        grouped = defaultdict(list)
        for alert in self.alerts:
            grouped[alert['severity']].append(alert)
        return dict(grouped)
    
    def print_alerts(self):
        """Print alerts in readable format"""
        if not self.alerts:
            print("[*] No alerts generated")
            return
        
        severity_colors = {
            'CRITICAL': '🔴',
            'HIGH': '🟠',
            'MEDIUM': '🟡',
            'LOW': '🟢'
        }
        
        print("\n" + "="*80)
        print("SECURITY ALERTS")
        print("="*80)
        
        for alert in self.alerts:
            severity = alert['severity']
            color = severity_colors.get(severity, '')
            print(f"\n{color} [{severity}] {alert['type']}")
            print(f"   Source IP: {alert['source_ip']}")
            print(f"   Description: {alert['description']}")
            print(f"   Time: {alert['timestamp']}")
        
        print("\n" + "="*80)
    
    def save_alerts(self, filename="security_alerts.json"):
        """Save alerts to file"""
        with open(filename, 'w') as f:
            json.dump(self.alerts, f, indent=2)
        print(f"[+] Alerts saved to {filename}")


if __name__ == "__main__":
    # Example usage
    sample_packets = [
        {'src_ip': '192.168.1.100', 'dst_port': 80, 'flags': 'S', 'protocol': 'TCP'},
        {'src_ip': '192.168.1.100', 'dst_port': 81, 'flags': 'S', 'protocol': 'TCP'},
    ]
    
    detector = AnomalyDetector()
    alerts = detector.detect_anomalies(sample_packets)
    detector.print_alerts()
