"""
Traffic Analysis Module
Analyzes network traffic patterns and generates insights
"""

import json
from collections import defaultdict
from datetime import datetime

class TrafficAnalyzer:
    def __init__(self):
        self.traffic_data = []
        self.analysis_results = {}
    
    def load_packets(self, packets_list):
        """Load packet data for analysis"""
        self.traffic_data = packets_list
        print(f"[*] Loaded {len(self.traffic_data)} packets for analysis")
    
    def analyze_traffic(self):
        """Perform traffic analysis"""
        if not self.traffic_data:
            print("[-] No packet data loaded!")
            return None
        
        print("[*] Analyzing traffic patterns...")
        
        analysis = {
            'timestamp': datetime.now().isoformat(),
            'total_packets': len(self.traffic_data),
            'protocol_breakdown': self._analyze_protocols(),
            'port_analysis': self._analyze_ports(),
            'ip_communication': self._analyze_ip_pairs(),
            'bandwidth_usage': self._analyze_bandwidth()
        }
        
        self.analysis_results = analysis
        print("[+] Traffic analysis complete")
        return analysis
    
    def _analyze_protocols(self):
        """Analyze protocol distribution"""
        protocol_count = defaultdict(int)
        
        for packet in self.traffic_data:
            protocol = packet.get('protocol', 'Unknown')
            protocol_count[protocol] += 1
        
        total = sum(protocol_count.values())
        protocol_dist = {
            protocol: {
                'count': count,
                'percentage': round((count/total)*100, 2)
            }
            for protocol, count in protocol_count.items()
        }
        
        return protocol_dist
    
    def _analyze_ports(self):
        """Analyze port usage"""
        port_count = defaultdict(int)
        
        for packet in self.traffic_data:
            if packet.get('dst_port'):
                port = packet['dst_port']
                port_count[port] += 1
        
        # Get top 10 ports
        top_ports = sorted(
            port_count.items(),
            key=lambda x: x[1],
            reverse=True
        )[:10]
        
        return {
            'total_unique_ports': len(port_count),
            'top_ports': [{'port': port, 'connections': count} for port, count in top_ports]
        }
    
    def _analyze_ip_pairs(self):
        """Analyze IP communication pairs"""
        ip_pairs = defaultdict(int)
        
        for packet in self.traffic_data:
            src = packet.get('src_ip')
            dst = packet.get('dst_ip')
            if src and dst:
                pair = f"{src} -> {dst}"
                ip_pairs[pair] += 1
        
        # Get top 10 communication pairs
        top_pairs = sorted(
            ip_pairs.items(),
            key=lambda x: x[1],
            reverse=True
        )[:10]
        
        return {
            'total_unique_pairs': len(ip_pairs),
            'top_conversations': [{'pair': pair, 'packets': count} for pair, count in top_pairs]
        }
    
    def _analyze_bandwidth(self):
        """Analyze bandwidth usage"""
        ip_bandwidth = defaultdict(int)
        
        for packet in self.traffic_data:
            src = packet.get('src_ip')
            size = packet.get('size', 0)
            if src:
                ip_bandwidth[src] += size
        
        # Get top 5 by bandwidth
        top_bandwidth = sorted(
            ip_bandwidth.items(),
            key=lambda x: x[1],
            reverse=True
        )[:5]
        
        total_bytes = sum(ip_bandwidth.values())
        
        return {
            'total_bytes': total_bytes,
            'total_mb': round(total_bytes / (1024*1024), 2),
            'top_users': [
                {
                    'ip': ip,
                    'bytes': bytes_used,
                    'mb': round(bytes_used / (1024*1024), 2)
                }
                for ip, bytes_used in top_bandwidth
            ]
        }
    
    def print_analysis(self):
        """Print analysis results in readable format"""
        if not self.analysis_results:
            print("[-] No analysis results available")
            return
        
        result = self.analysis_results
        
        print("\n" + "="*60)
        print("TRAFFIC ANALYSIS REPORT")
        print("="*60)
        
        print(f"\nTotal Packets Analyzed: {result['total_packets']}")
        
        print("\n[+] Protocol Distribution:")
        for protocol, data in result['protocol_breakdown'].items():
            print(f"  {protocol:10} : {data['count']:6} packets ({data['percentage']:5.1f}%)")
        
        print("\n[+] Top Ports:")
        for item in result['port_analysis']['top_ports']:
            print(f"  Port {item['port']:5} : {item['connections']:6} connections")
        
        print("\n[+] Top Communication Pairs:")
        for item in result['ip_communication']['top_conversations'][:5]:
            print(f"  {item['pair']:35} : {item['packets']:6} packets")
        
        print("\n[+] Bandwidth Usage:")
        print(f"  Total: {result['bandwidth_usage']['total_mb']} MB")
        for item in result['bandwidth_usage']['top_users']:
            print(f"  {item['ip']:15} : {item['mb']:8.2f} MB")
        
        print("\n" + "="*60)
    
    def save_analysis(self, filename="traffic_analysis.json"):
        """Save analysis results"""
        with open(filename, 'w') as f:
            json.dump(self.analysis_results, f, indent=2)
        print(f"[+] Analysis saved to {filename}")


if __name__ == "__main__":
    # Example usage
    sample_packets = [
        {
            'src_ip': '192.168.1.100',
            'dst_ip': '192.168.1.1',
            'protocol': 'TCP',
            'dst_port': 80,
            'size': 1500
        }
    ]
    
    analyzer = TrafficAnalyzer()
    analyzer.load_packets(sample_packets)
    analyzer.analyze_traffic()
    analyzer.print_analysis()
