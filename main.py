"""
Main Application - Command Line Interface
Orchestrates all network monitoring modules
Run with: python main.py
"""

import json
import sys
from datetime import datetime

# Import modules
from network_scanner import NetworkScanner
from packet_analyzer import PacketAnalyzer
from traffic_analyzer import TrafficAnalyzer
from anomaly_detector import AnomalyDetector

class NetworkMonitoringApp:
    def __init__(self):
        self.scanner = NetworkScanner()
        self.packet_analyzer = PacketAnalyzer()
        self.traffic_analyzer = TrafficAnalyzer()
        self.anomaly_detector = AnomalyDetector()
        self.session_data = {}
    
    def display_menu(self):
        """Display main menu"""
        print("\n" + "="*60)
        print("NETWORK MONITORING AND TRAFFIC ANALYSIS TOOL")
        print("="*60)
        print("\n[1] Scan Network for Active Devices")
        print("[2] Capture Network Packets")
        print("[3] Analyze Traffic Patterns")
        print("[4] Detect Anomalies & Threats")
        print("[5] View All Results")
        print("[6] Generate Report")
        print("[7] Exit")
        print("\n" + "="*60)
    
    def run(self):
        """Run the application"""
        print("\n[*] Network Monitoring Tool Started")
        
        while True:
            self.display_menu()
            choice = input("\nEnter your choice (1-7): ").strip()
            
            if choice == '1':
                self.perform_network_scan()
            elif choice == '2':
                self.perform_packet_capture()
            elif choice == '3':
                self.perform_traffic_analysis()
            elif choice == '4':
                self.perform_anomaly_detection()
            elif choice == '5':
                self.view_all_results()
            elif choice == '6':
                self.generate_report()
            elif choice == '7':
                print("\n[*] Exiting application...")
                sys.exit(0)
            else:
                print("[-] Invalid choice. Please try again.")
    
    def perform_network_scan(self):
        """Execute network scanning"""
        print("\n[*] NETWORK SCANNING MODULE")
        print("-" * 60)
        
        ip_range = input("Enter network range (default: 192.168.1.0/24): ").strip()
        if not ip_range:
            ip_range = "192.168.1.0/24"
        
        devices = self.scanner.scan_network(ip_range)
        self.session_data['devices'] = devices
        
        if devices:
            print("\n[+] Discovered Devices:")
            print(f"{'IP Address':<15} {'MAC Address':<17} {'Hostname':<20}")
            print("-" * 52)
            for device in devices:
                print(f"{device['ip']:<15} {device['mac']:<17} {device['hostname']:<20}")
            
            self.scanner.save_results("scan_results.json")
    
    def perform_packet_capture(self):
        """Execute packet capture"""
        print("\n[*] PACKET CAPTURE MODULE")
        print("-" * 60)
        print("Note: This requires Administrator/Root privileges!")
        
        try:
            packet_count = input("Number of packets to capture (default: 100): ").strip()
            packet_count = int(packet_count) if packet_count else 100
            
            timeout = input("Timeout in seconds (default: 60): ").strip()
            timeout = int(timeout) if timeout else 60
            
            self.packet_analyzer.capture_packets(packet_count, timeout)
            self.session_data['packets'] = self.packet_analyzer.packets
            
            stats = self.packet_analyzer.get_statistics()
            print(f"\n[+] Capture Statistics:")
            print(f"  Total Packets: {stats['total_packets']}")
            print(f"  Protocols: {stats['protocol_distribution']}")
            
            self.packet_analyzer.save_packets("captured_packets.json")
            
        except PermissionError:
            print("[-] Error: Administrator/Root privileges required!")
            print("[*] Windows: Run as Administrator")
            print("[*] Linux: Use sudo")
        except ValueError:
            print("[-] Invalid input. Please enter numbers.")
    
    def perform_traffic_analysis(self):
        """Execute traffic analysis"""
        print("\n[*] TRAFFIC ANALYSIS MODULE")
        print("-" * 60)
        
        if 'packets' not in self.session_data or not self.session_data['packets']:
            print("[-] No packet data available. Please capture packets first.")
            return
        
        self.traffic_analyzer.load_packets(self.session_data['packets'])
        analysis = self.traffic_analyzer.analyze_traffic()
        
        if analysis:
            self.traffic_analyzer.print_analysis()
            self.traffic_analyzer.save_analysis("traffic_analysis.json")
    
    def perform_anomaly_detection(self):
        """Execute anomaly detection"""
        print("\n[*] ANOMALY DETECTION MODULE")
        print("-" * 60)
        
        if 'packets' not in self.session_data or not self.session_data['packets']:
            print("[-] No packet data available. Please capture packets first.")
            return
        
        ip_stats = dict(self.packet_analyzer.ip_stats) if self.packet_analyzer.ip_stats else None
        alerts = self.anomaly_detector.detect_anomalies(
            self.session_data['packets'],
            ip_stats
        )
        self.session_data['alerts'] = alerts
        
        self.anomaly_detector.print_alerts()
        self.anomaly_detector.save_alerts("security_alerts.json")
    
    def view_all_results(self):
        """Display all collected results"""
        print("\n[*] SESSION RESULTS")
        print("="*60)
        
        if 'devices' in self.session_data and self.session_data['devices']:
            print(f"\n[+] Scanned Devices: {len(self.session_data['devices'])}")
        
        if 'packets' in self.session_data and self.session_data['packets']:
            print(f"[+] Captured Packets: {len(self.session_data['packets'])}")
        
        if 'alerts' in self.session_data and self.session_data['alerts']:
            print(f"[+] Security Alerts: {len(self.session_data['alerts'])}")
            alert_summary = self.anomaly_detector.get_alerts_by_severity()
            for severity, alerts in alert_summary.items():
                print(f"    {severity}: {len(alerts)}")
    
    def generate_report(self):
        """Generate comprehensive report"""
        print("\n[*] GENERATING REPORT")
        print("-" * 60)
        
        report = {
            'timestamp': datetime.now().isoformat(),
            'device_scan': self.scanner.get_device_summary() if self.session_data.get('devices') else None,
            'packet_capture': self.packet_analyzer.get_statistics() if self.session_data.get('packets') else None,
            'alerts': self.session_data.get('alerts', [])
        }
        
        filename = f"network_monitoring_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"[+] Report saved to {filename}")
        print("\nReport Summary:")
        print(f"  Timestamp: {report['timestamp']}")
        if report['device_scan']:
            print(f"  Devices Found: {report['device_scan']['total_devices']}")
        if report['packet_capture']:
            print(f"  Packets Captured: {report['packet_capture']['total_packets']}")
        print(f"  Alerts Generated: {len(report['alerts'])}")


if __name__ == "__main__":
    app = NetworkMonitoringApp()
    
    # Check if running with elevated privileges on Windows
    try:
        import os
        import platform
        if platform.system() == 'Windows':
            if os.getuid() != 0:
                print("[!] Warning: For packet capture, please run as Administrator")
    except:
        pass
    
    app.run()
