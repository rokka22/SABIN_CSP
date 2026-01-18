"""
Packet Capture and Analysis Module
Captures and analyzes network packets using Scapy
"""

from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP
from collections import defaultdict
import json
from datetime import datetime

class PacketAnalyzer:
    def __init__(self):
        self.packets = []
        self.packet_stats = defaultdict(int)
        self.ip_stats = defaultdict(lambda: {'packets': 0, 'bytes': 0})
        self.protocol_stats = defaultdict(int)
        self.start_time = None
    
    def packet_callback(self, packet):
        """Callback function for each captured packet"""
        if IP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            protocol = packet[IP].proto
            
            # Extract packet information
            packet_info = {
                'timestamp': datetime.now().isoformat(),
                'src_ip': ip_src,
                'dst_ip': ip_dst,
                'src_port': None,
                'dst_port': None,
                'protocol': self.get_protocol_name(protocol),
                'size': len(packet),
                'flags': None
            }
            
            # Extract protocol-specific information
            if TCP in packet:
                packet_info['src_port'] = packet[TCP].sport
                packet_info['dst_port'] = packet[TCP].dport
                packet_info['flags'] = str(packet[TCP].flags)
                self.protocol_stats['TCP'] += 1
            elif UDP in packet:
                packet_info['src_port'] = packet[UDP].sport
                packet_info['dst_port'] = packet[UDP].dport
                self.protocol_stats['UDP'] += 1
            elif ICMP in packet:
                packet_info['protocol'] = 'ICMP'
                self.protocol_stats['ICMP'] += 1
            elif ARP in packet:
                packet_info['protocol'] = 'ARP'
                self.protocol_stats['ARP'] += 1
            
            # Update statistics
            self.packets.append(packet_info)
            self.ip_stats[ip_src]['packets'] += 1
            self.ip_stats[ip_src]['bytes'] += len(packet)
            self.ip_stats[ip_dst]['packets'] += 1
            self.ip_stats[ip_dst]['bytes'] += len(packet)
    
    def get_protocol_name(self, protocol_num):
        """Convert protocol number to name"""
        protocols = {
            6: 'TCP',
            17: 'UDP',
            1: 'ICMP',
            255: 'ARP'
        }
        return protocols.get(protocol_num, f'Other({protocol_num})')
    
    def capture_packets(self, packet_count=100, timeout=60):
        """
        Capture network packets
        packet_count: Number of packets to capture
        timeout: Timeout in seconds
        """
        print(f"[*] Starting packet capture (will capture {packet_count} packets)...")
        print("[*] Note: Requires administrator/root privileges!")
        
        self.start_time = datetime.now()
        
        try:
            sniff(
                prn=self.packet_callback,
                count=packet_count,
                timeout=timeout,
                store=False
            )
            print(f"[+] Captured {len(self.packets)} packets")
        except PermissionError:
            print("[-] Error: Administrator/Root privileges required!")
            print("[*] Please run with admin privileges")
        except Exception as e:
            print(f"[-] Capture error: {e}")
    
    def get_statistics(self):
        """Get packet capture statistics"""
        return {
            'total_packets': len(self.packets),
            'protocol_distribution': dict(self.protocol_stats),
            'top_ips': self.get_top_ips(5),
            'capture_time': self.start_time.isoformat() if self.start_time else None
        }
    
    def get_top_ips(self, count=5):
        """Get top IPs by packet count"""
        sorted_ips = sorted(
            self.ip_stats.items(),
            key=lambda x: x[1]['packets'],
            reverse=True
        )
        return sorted_ips[:count]
    
    def save_packets(self, filename="captured_packets.json"):
        """Save captured packets to JSON"""
        with open(filename, 'w') as f:
            json.dump(self.packets[:1000], f, indent=2)  # Save first 1000
        print(f"[+] Packets saved to {filename}")
    
    def get_recent_packets(self, count=10):
        """Get recent captured packets"""
        return self.packets[-count:]


if __name__ == "__main__":
    analyzer = PacketAnalyzer()
    analyzer.capture_packets(packet_count=50)
    
    print("\n[+] Packet Statistics:")
    stats = analyzer.get_statistics()
    print(f"  Total Packets: {stats['total_packets']}")
    print(f"  Protocols: {stats['protocol_distribution']}")
    print(f"\n  Top IPs by traffic:")
    for ip, data in stats['top_ips']:
        print(f"    {ip}: {data['packets']} packets, {data['bytes']} bytes")
    
    analyzer.save_packets()
