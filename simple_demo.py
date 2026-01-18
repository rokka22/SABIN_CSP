"""
Simple Demo Script - Network Monitoring Demonstration
Simplified version with no external dependencies
Run with: python simple_demo.py
"""

import json
from datetime import datetime
from collections import defaultdict

print("""
╔════════════════════════════════════════════════════════════════╗
║                                                                ║
║      NETWORK MONITORING & TRAFFIC ANALYSIS TOOL                ║
║                    DEMONSTRATION MODE                          ║
║                                                                ║
║   This demo shows tool capabilities with sample data           ║
║   For live monitoring, use main.py with admin privileges       ║
║                                                                ║
╚════════════════════════════════════════════════════════════════╝
""")

def demo_1_network_scanner():
    """Demonstrate network scanning"""
    print("\n" + "="*70)
    print("DEMO 1: NETWORK SCANNING MODULE")
    print("="*70)
    
    # Simulate scan results
    sample_devices = [
        {
            'ip': '192.168.1.1',
            'mac': '00:11:22:33:44:55',
            'hostname': 'gateway.local',
            'ports': [80, 443],
            'os': 'Linux',
            'timestamp': datetime.now().isoformat()
        },
        {
            'ip': '192.168.1.100',
            'mac': 'AA:BB:CC:DD:EE:FF',
            'hostname': 'desktop-pc.local',
            'ports': [135, 139, 445],
            'os': 'Windows 10',
            'timestamp': datetime.now().isoformat()
        },
        {
            'ip': '192.168.1.101',
            'mac': '11:22:33:44:55:66',
            'hostname': 'laptop.local',
            'ports': [22, 80],
            'os': 'Linux',
            'timestamp': datetime.now().isoformat()
        },
        {
            'ip': '192.168.1.50',
            'mac': '22:33:44:55:66:77',
            'hostname': 'printer.local',
            'ports': [9100],
            'os': 'CUPS Print Server',
            'timestamp': datetime.now().isoformat()
        }
    ]
    
    print("\n[+] Discovered Network Devices:")
    print(f"{'IP Address':<15} {'MAC Address':<17} {'Hostname':<20} {'OS':<20}")
    print("-" * 75)
    
    for device in sample_devices:
        print(f"{device['ip']:<15} {device['mac']:<17} {device['hostname']:<20} {device['os']:<20}")
    
    print(f"\n[✓] Total devices found: {len(sample_devices)}")
    
    # Save results
    with open('demo_network_devices.json', 'w') as f:
        json.dump(sample_devices, f, indent=2)
    print("[✓] Results saved to demo_network_devices.json")
    
    return sample_devices

def demo_2_packet_capture():
    """Demonstrate packet capture and statistics"""
    print("\n" + "="*70)
    print("DEMO 2: PACKET CAPTURE & ANALYSIS")
    print("="*70)
    
    # Create sample packet data
    sample_packets = [
        # Normal HTTP traffic
        {'src_ip': '192.168.1.100', 'dst_ip': '8.8.8.8', 'protocol': 'TCP', 'dst_port': 80, 'size': 1500, 'flags': 'PSH'},
        {'src_ip': '192.168.1.100', 'dst_ip': '8.8.8.8', 'protocol': 'TCP', 'dst_port': 443, 'size': 2000, 'flags': 'PSH'},
        {'src_ip': '192.168.1.100', 'dst_ip': '8.8.8.8', 'protocol': 'TCP', 'dst_port': 443, 'size': 2000, 'flags': 'PSH'},
        
        # DNS queries
        {'src_ip': '192.168.1.100', 'dst_ip': '8.8.8.8', 'protocol': 'UDP', 'dst_port': 53, 'size': 150, 'flags': None},
        {'src_ip': '192.168.1.101', 'dst_ip': '8.8.8.8', 'protocol': 'UDP', 'dst_port': 53, 'size': 150, 'flags': None},
        
        # More HTTP/HTTPS traffic
        {'src_ip': '192.168.1.101', 'dst_ip': '142.251.41.14', 'protocol': 'TCP', 'dst_port': 443, 'size': 1800, 'flags': 'PSH'},
        {'src_ip': '192.168.1.50', 'dst_ip': '8.8.8.8', 'protocol': 'UDP', 'dst_port': 53, 'size': 150, 'flags': None},
        {'src_ip': '192.168.1.1', 'dst_ip': '192.168.1.100', 'protocol': 'TCP', 'dst_port': 22, 'size': 100, 'flags': 'PSH'},
        
        # Local traffic
        {'src_ip': '192.168.1.100', 'dst_ip': '192.168.1.1', 'protocol': 'TCP', 'dst_port': 22, 'size': 100, 'flags': 'PSH'},
    ]
    
    print(f"\n[+] Captured {len(sample_packets)} Network Packets")
    print(f"\n{'Src IP':<15} {'Dst IP':<15} {'Protocol':<8} {'Port':<6} {'Size':<6} {'Flags':<8}")
    print("-" * 70)
    
    for packet in sample_packets[:15]:  # Show first 15
        flags = packet.get('flags', '-') or '-'
        dst_port = str(packet.get('dst_port', '-'))
        print(f"{packet['src_ip']:<15} {packet['dst_ip']:<15} {packet['protocol']:<8} {dst_port:<6} {packet['size']:<6} {flags:<8}")
    
    # Protocol statistics
    protocol_count = defaultdict(int)
    for packet in sample_packets:
        protocol_count[packet['protocol']] += 1
    
    print(f"\n[+] Protocol Distribution:")
    total = sum(protocol_count.values())
    for protocol, count in sorted(protocol_count.items()):
        percentage = (count/total)*100
        print(f"  {protocol:<10}: {count:>3} packets ({percentage:>5.1f}%)")
    
    # IP statistics
    ip_stats = defaultdict(lambda: {'packets': 0, 'bytes': 0})
    for packet in sample_packets:
        src = packet['src_ip']
        ip_stats[src]['packets'] += 1
        ip_stats[src]['bytes'] += packet['size']
    
    print(f"\n[+] Top IPs by Traffic:")
    top_ips = sorted(ip_stats.items(), key=lambda x: x[1]['bytes'], reverse=True)[:5]
    for ip, stats in top_ips:
        mb = stats['bytes'] / (1024*1024)
        print(f"  {ip:<15}: {stats['packets']:>4} packets, {mb:>8.2f} MB")
    
    # Save results
    with open('demo_captured_packets.json', 'w') as f:
        json.dump(sample_packets, f, indent=2)
    print("\n[✓] Packets saved to demo_captured_packets.json")
    
    return sample_packets, dict(ip_stats)

def demo_3_traffic_analysis(packets, ip_stats):
    """Demonstrate traffic analysis"""
    print("\n" + "="*70)
    print("DEMO 3: TRAFFIC ANALYSIS & INSIGHTS")
    print("="*70)
    
    # Port analysis
    port_count = defaultdict(int)
    for packet in packets:
        if packet.get('dst_port'):
            port_count[packet['dst_port']] += 1
    
    print(f"\n[+] Top Destination Ports:")
    top_ports = sorted(port_count.items(), key=lambda x: x[1], reverse=True)[:10]
    for port, count in top_ports:
        service = {
            22: 'SSH', 53: 'DNS', 80: 'HTTP', 
            443: 'HTTPS', 445: 'SMB', 3306: 'MySQL',
            5432: 'PostgreSQL', 9100: 'Print'
        }.get(port, 'Unknown')
        print(f"  Port {port:<5} ({service:<12}): {count:>3} connections")
    
    # IP communication pairs
    ip_pairs = defaultdict(int)
    for packet in packets:
        src = packet['src_ip']
        dst = packet['dst_ip']
        pair = f"{src} -> {dst}"
        ip_pairs[pair] += 1
    
    print(f"\n[+] Top Communication Pairs:")
    top_pairs = sorted(ip_pairs.items(), key=lambda x: x[1], reverse=True)[:8]
    for pair, count in top_pairs:
        print(f"  {pair:<35}: {count:>3} packets")
    
    # Total bandwidth
    total_bytes = sum(p['size'] for p in packets)
    total_mb = total_bytes / (1024*1024)
    
    print(f"\n[+] Bandwidth Analysis:")
    print(f"  Total Data: {total_bytes} bytes ({total_mb:.2f} MB)")
    print(f"  Average Packet Size: {total_bytes//len(packets)} bytes")
    
    # Save analysis
    protocol_dist = defaultdict(int)
    for p in packets:
        protocol_dist[p['protocol']] += 1
    
    analysis = {
        'timestamp': datetime.now().isoformat(),
        'total_packets': len(packets),
        'total_bytes': total_bytes,
        'protocol_distribution': dict(protocol_dist),
        'top_ports': [{'port': p, 'count': c} for p, c in top_ports],
        'bandwidth_mb': total_mb
    }
    
    with open('demo_traffic_analysis.json', 'w') as f:
        json.dump(analysis, f, indent=2)
    print("\n[✓] Analysis saved to demo_traffic_analysis.json")

def demo_4_anomaly_detection(packets, ip_stats):
    """Demonstrate anomaly detection"""
    print("\n" + "="*70)
    print("DEMO 4: ANOMALY DETECTION & THREAT IDENTIFICATION")
    print("="*70)
    
    alerts = []
    
    # Check for suspicious patterns
    print(f"\n[*] Scanning for threats...")
    
    # Simulate some threat detection
    suspicious_ports = {23, 135, 139, 445, 21}
    port_activity = defaultdict(set)
    
    for packet in packets:
        src_ip = packet.get('src_ip')
        dst_port = packet.get('dst_port')
        if src_ip and dst_port in suspicious_ports:
            port_activity[src_ip].add(dst_port)
            alerts.append({
                'timestamp': datetime.now().isoformat(),
                'type': 'SUSPICIOUS_PORT',
                'source_ip': src_ip,
                'description': f'Connection to port {dst_port}',
                'severity': 'LOW'
            })
    
    print(f"\n[+] Security Alerts Generated:")
    print(f"{'Severity':<10} {'Type':<20} {'Source IP':<15} {'Description':<35}")
    print("-" * 80)
    
    if alerts:
        for alert in alerts:
            print(f"{alert['severity']:<10} {alert['type']:<20} {alert['source_ip']:<15} {alert['description']:<35}")
    else:
        print("  [✓] No suspicious activity detected in sample data")
    
    # Summary
    print(f"\n[+] Alert Summary:")
    print(f"    Total Alerts: {len(alerts)}")
    
    severity_count = defaultdict(int)
    for alert in alerts:
        severity_count[alert['severity']] += 1
    
    for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
        count = severity_count.get(severity, 0)
        if count > 0:
            print(f"    {severity}: {count}")
    
    # Save alerts
    with open('demo_security_alerts.json', 'w') as f:
        json.dump(alerts, f, indent=2)
    
    if alerts:
        print("\n[✓] Alerts saved to demo_security_alerts.json")
    
    return alerts

def main():
    """Run the complete demonstration"""
    
    # Run all demonstrations
    devices = demo_1_network_scanner()
    packets, ip_stats = demo_2_packet_capture()
    demo_3_traffic_analysis(packets, ip_stats)
    alerts = demo_4_anomaly_detection(packets, ip_stats)
    
    # Final summary
    print("\n" + "="*70)
    print("DEMO COMPLETE!")
    print("="*70)
    
    print(f"""
[✓] Demonstration Complete!

Generated Files:
  • demo_network_devices.json      - Scanned network devices
  • demo_captured_packets.json     - Captured packet data
  • demo_traffic_analysis.json     - Traffic analysis results
  • demo_security_alerts.json      - Security alerts log

Project Structure:
  • network_scanner.py             - Network device discovery
  • packet_analyzer.py             - Packet capture module
  • traffic_analyzer.py            - Traffic analysis engine
  • anomaly_detector.py            - Threat detection module
  • main.py                        - CLI application
  • app_dashboard.py               - Web dashboard (Streamlit)
  • demo.py                        - Full demo (requires packages)
  • simple_demo.py                 - This simplified demo

How to Use:

[1] Install Dependencies:
    pip install -r requirements.txt

[2] Run Interactive CLI:
    python main.py

[3] Run Web Dashboard:
    streamlit run app_dashboard.py

[4] Run Full Demo (with packages):
    python demo.py

[5] Run This Simple Demo (no dependencies):
    python simple_demo.py

Important Notes:
  ⚠️  Packet capture requires Administrator/Root privileges
  ⚠️  Only monitor networks you own or have permission
  ✓  This is an educational cybersecurity tool

For more information, see README.md
""")

if __name__ == "__main__":
    main()
