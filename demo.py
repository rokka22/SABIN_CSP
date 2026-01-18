"""
Simple Demo Script - Network Monitoring Demonstration
This script demonstrates the features without requiring admin privileges
Run with: python demo.py
"""

import json
from datetime import datetime
from network_scanner import NetworkScanner
from traffic_analyzer import TrafficAnalyzer
from anomaly_detector import AnomalyDetector

def create_sample_packets():
    """Create sample packet data for demonstration"""
    sample_packets = [
        # Normal HTTP traffic
        {'src_ip': '192.168.1.100', 'dst_ip': '8.8.8.8', 'protocol': 'TCP', 'dst_port': 80, 'size': 1500, 'flags': 'PSH'},
        {'src_ip': '192.168.1.100', 'dst_ip': '8.8.8.8', 'protocol': 'TCP', 'dst_port': 443, 'size': 2000, 'flags': 'PSH'},
        
        # DNS queries
        {'src_ip': '192.168.1.100', 'dst_ip': '8.8.8.8', 'protocol': 'UDP', 'dst_port': 53, 'size': 150, 'flags': None},
        {'src_ip': '192.168.1.101', 'dst_ip': '8.8.8.8', 'protocol': 'UDP', 'dst_port': 53, 'size': 150, 'flags': None},
        
        # Suspicious port scanning activity
        {'src_ip': '192.168.1.50', 'dst_ip': '192.168.1.100', 'protocol': 'TCP', 'dst_port': 22, 'size': 64, 'flags': 'S'},
        {'src_ip': '192.168.1.50', 'dst_ip': '192.168.1.100', 'protocol': 'TCP', 'dst_port': 23, 'size': 64, 'flags': 'S'},
        {'src_ip': '192.168.1.50', 'dst_ip': '192.168.1.100', 'protocol': 'TCP', 'dst_port': 25, 'size': 64, 'flags': 'S'},
        {'src_ip': '192.168.1.50', 'dst_ip': '192.168.1.100', 'protocol': 'TCP', 'dst_port': 445, 'size': 64, 'flags': 'S'},
        {'src_ip': '192.168.1.50', 'dst_ip': '192.168.1.100', 'protocol': 'TCP', 'dst_port': 135, 'size': 64, 'flags': 'S'},
        
        # SYN flood attempt
        {'src_ip': '10.0.0.5', 'dst_ip': '192.168.1.100', 'protocol': 'TCP', 'dst_port': 80, 'size': 64, 'flags': 'S'},
        {'src_ip': '10.0.0.5', 'dst_ip': '192.168.1.100', 'protocol': 'TCP', 'dst_port': 80, 'size': 64, 'flags': 'S'},
        {'src_ip': '10.0.0.5', 'dst_ip': '192.168.1.100', 'protocol': 'TCP', 'dst_port': 80, 'size': 64, 'flags': 'S'},
        {'src_ip': '10.0.0.5', 'dst_ip': '192.168.1.100', 'protocol': 'TCP', 'dst_port': 80, 'size': 64, 'flags': 'S'},
        {'src_ip': '10.0.0.5', 'dst_ip': '192.168.1.100', 'protocol': 'TCP', 'dst_port': 80, 'size': 64, 'flags': 'S'},
        
        # ARP activity
        {'src_ip': '192.168.1.1', 'dst_ip': '192.168.1.100', 'protocol': 'ARP', 'dst_port': None, 'size': 42, 'flags': None},
    ]
    
    # Add timestamps
    for packet in sample_packets:
        packet['timestamp'] = datetime.now().isoformat()
    
    return sample_packets

def create_sample_ip_stats():
    """Create sample IP statistics"""
    return {
        '192.168.1.100': {'packets': 150, 'bytes': 500000},
        '192.168.1.101': {'packets': 80, 'bytes': 200000},
        '10.0.0.5': {'packets': 200, 'bytes': 50000},
        '192.168.1.50': {'packets': 120, 'bytes': 100000},
        '8.8.8.8': {'packets': 500, 'bytes': 2000000},
    }

def print_demo_banner():
    """Print demo banner"""
    banner = """
    ╔════════════════════════════════════════════════════════════════╗
    ║                                                                ║
    ║      NETWORK MONITORING & TRAFFIC ANALYSIS TOOL                ║
    ║                    DEMONSTRATION MODE                          ║
    ║                                                                ║
    ║   This demo uses sample data to show tool capabilities         ║
    ║   For live monitoring, use main.py with admin privileges       ║
    ║                                                                ║
    ╚════════════════════════════════════════════════════════════════╝
    """
    print(banner)

def demo_network_scanner():
    """Demonstrate network scanning"""
    print("\n" + "="*70)
    print("DEMO 1: NETWORK SCANNING MODULE")
    print("="*70)
    
    scanner = NetworkScanner()
    
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
        }
    ]
    
    scanner.devices = sample_devices
    scanner.scan_timestamp = datetime.now()
    
    print("\n[+] Discovered Network Devices:")
    print(f"{'IP Address':<15} {'MAC Address':<17} {'Hostname':<20} {'OS':<15}")
    print("-" * 70)
    
    for device in sample_devices:
        print(f"{device['ip']:<15} {device['mac']:<17} {device['hostname']:<20} {device['os']:<15}")
    
    print(f"\n[✓] Total devices found: {len(sample_devices)}")

def demo_traffic_analysis():
    """Demonstrate traffic analysis"""
    print("\n" + "="*70)
    print("DEMO 2: TRAFFIC ANALYSIS MODULE")
    print("="*70)
    
    packets = create_sample_packets()
    ip_stats = create_sample_ip_stats()
    
    analyzer = TrafficAnalyzer()
    analyzer.load_packets(packets)
    analysis = analyzer.analyze_traffic()
    
    analyzer.print_analysis()

def demo_anomaly_detection():
    """Demonstrate anomaly detection"""
    print("\n" + "="*70)
    print("DEMO 3: ANOMALY DETECTION & THREAT IDENTIFICATION")
    print("="*70)
    
    packets = create_sample_packets()
    ip_stats = create_sample_ip_stats()
    
    detector = AnomalyDetector()
    alerts = detector.detect_anomalies(packets, ip_stats)
    
    detector.print_alerts()
    
    print("\n[+] Alert Summary:")
    print(f"    Total Alerts: {len(alerts)}")
    
    by_severity = detector.get_alerts_by_severity()
    for severity, severity_alerts in by_severity.items():
        print(f"    {severity}: {len(severity_alerts)}")

def save_demo_results():
    """Save demo results to files"""
    print("\n" + "="*70)
    print("DEMO 4: SAVING RESULTS TO FILES")
    print("="*70)
    
    packets = create_sample_packets()
    ip_stats = create_sample_ip_stats()
    
    # Save packets
    with open('demo_packets.json', 'w') as f:
        json.dump(packets, f, indent=2)
    print("[✓] Sample packets saved to demo_packets.json")
    
    # Save traffic analysis
    analyzer = TrafficAnalyzer()
    analyzer.load_packets(packets)
    analyzer.analyze_traffic()
    analyzer.save_analysis('demo_traffic_analysis.json')
    
    # Save alerts
    detector = AnomalyDetector()
    detector.detect_anomalies(packets, ip_stats)
    detector.save_alerts('demo_security_alerts.json')

def print_instructions():
    """Print usage instructions"""
    print("\n" + "="*70)
    print("NEXT STEPS - HOW TO USE THE REAL APPLICATION")
    print("="*70)
    
    print("""
[1] COMMAND-LINE INTERFACE (main.py):
    python main.py
    - Interactive menu-driven interface
    - Perform network scans
    - Capture real network packets (requires admin)
    - Analyze traffic patterns
    - Detect anomalies and threats
    - Generate comprehensive reports

[2] WEB DASHBOARD (app_dashboard.py):
    pip install streamlit
    streamlit run app_dashboard.py
    - Modern web-based interface
    - Real-time network monitoring
    - Interactive charts and visualizations
    - Download reports and data exports
    - User-friendly threat alerts

[3] REQUIREMENTS:
    pip install -r requirements.txt
    
[4] IMPORTANT NOTES:
    ⚠️  Packet capture requires Administrator/Root privileges:
        • Windows: Run Command Prompt as Administrator
        • Linux: Use 'sudo' or run with root privileges
        • macOS: May require elevated privileges for packet capture
    
    ⚠️  Only monitor networks you own or have permission to monitor
    ✓  This is an educational tool for learning cybersecurity

[5] PROJECT MODULES:
    • network_scanner.py      - Local network device discovery
    • packet_analyzer.py      - Network packet capture and analysis
    • traffic_analyzer.py     - Traffic pattern analysis
    • anomaly_detector.py     - Threat detection and alerts
    • main.py                - CLI application
    • app_dashboard.py        - Web dashboard (Streamlit)
    • demo.py                - This demonstration script

[6] OUTPUT FILES:
    • scan_results.json         - Network scan results
    • captured_packets.json     - Captured packet data
    • traffic_analysis.json     - Traffic analysis results
    • security_alerts.json      - Security alerts log
    • network_monitoring_report_*.json - Comprehensive reports
    """)

def main():
    """Run the demonstration"""
    print_demo_banner()
    
    # Run all demonstrations
    demo_network_scanner()
    demo_traffic_analysis()
    demo_anomaly_detection()
    save_demo_results()
    print_instructions()
    
    print("\n" + "="*70)
    print("DEMO COMPLETE!")
    print("="*70)
    print("\n[✓] Check the generated JSON files for detailed output")
    print("[✓] Run 'python main.py' for interactive tool")
    print("[✓] Run 'streamlit run app_dashboard.py' for web interface\n")

if __name__ == "__main__":
    main()
