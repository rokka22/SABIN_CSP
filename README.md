# Network Monitoring and Traffic Analysis Tool

A comprehensive Python-based network monitoring and cybersecurity analysis tool designed for educational purposes and learning practical cybersecurity skills.

## 📋 Project Overview

This tool enables you to:
- **Discover** all active devices on your network
- **Capture** and analyze live network traffic
- **Analyze** traffic patterns and protocols
- **Detect** suspicious activity and potential threats
- **Generate** detailed security reports

## ✨ Key Features

### 1. 🌐 Network Scanner Module
- Discover active devices on local networks using ARP
- Collect MAC addresses, hostnames, and OS information
- Display results in real-time
- Export device information to JSON/CSV formats

### 2. 📦 Packet Capture & Analysis Module
- Capture live network packets (requires admin privileges)
- Extract detailed packet information:
  - Source/Destination IP addresses
  - Source/Destination ports
  - Protocol types (TCP, UDP, ICMP, ARP)
  - Packet timestamps and sizes
  - TCP flags
- Analyze protocol distribution
- Track bandwidth usage per device

### 3. 📊 Traffic Analysis Module
- Compute packet statistics per device
- Analyze protocol distribution (TCP/UDP/ICMP)
- Identify top bandwidth consumers
- Track communication patterns between IPs
- Monitor port usage and services
- Generate comprehensive traffic insights

### 4. 🚨 Anomaly Detection & Threat Identification
- **Port Scanning Detection**: Identifies hosts scanning multiple ports
- **SYN Flood Detection**: Detects potential DDoS attacks
- **ARP Spoofing Detection**: Identifies suspicious ARP activity
- **Bandwidth Abuse Detection**: Flags excessive data transfers
- **Suspicious Port Monitoring**: Alerts on dangerous ports (SMB, Telnet, SSH)
- **Severity-Based Alerts**: CRITICAL, HIGH, MEDIUM, LOW

### 5. 📈 Dashboard & Reporting
- **Web Dashboard**: Modern Streamlit interface with interactive charts
- **CLI Interface**: Menu-driven command-line tool
- **Automated Reports**: Generate JSON/CSV reports
- **Alert Logs**: Track all security events with timestamps
- **Data Export**: Multiple export formats

## 📁 Project Structure

```
Network_Monitoring_Tool/
├── network_scanner.py          # Network device discovery (ARP-based)
├── packet_analyzer.py          # Live packet capture and analysis
├── traffic_analyzer.py         # Traffic pattern analysis engine
├── anomaly_detector.py         # Threat detection and alerts
├── main.py                     # Interactive CLI application
├── app_dashboard.py            # Streamlit web dashboard
├── demo.py                     # Full feature demonstration
├── simple_demo.py              # Simplified demo (no dependencies)
├── requirements.txt            # Python package dependencies
└── README.md                   # This file
```

## 🚀 Installation & Setup

### Step 1: System Requirements
- **Python 3.8+** - Download from https://www.python.org/
- **Administrator/Root Access** - Required for packet capture
- **Windows/Linux/macOS** - Cross-platform support

### Step 2: Install Python Dependencies

```bash
# Install all required packages
pip install -r requirements.txt

# Or install individually
pip install streamlit scapy pandas plotly numpy psutil
```

### Step 3: Install Optional Network Tools (Recommended)

**For Windows:**
- Download Nmap: https://nmap.org/download.html
- Download Wireshark: https://www.wireshark.org/download/

**For Linux:**
```bash
sudo apt-get update
sudo apt-get install nmap wireshark tcpdump
```

**For macOS:**
```bash
brew install nmap wireshark tcpdump
```

## 💻 Usage Guide

### Option 1: Interactive CLI Application (Recommended for Learning)

```bash
python main.py
```

**Features:**
- Menu-driven interface
- Network device scanning
- Live packet capture
- Traffic analysis
- Threat detection
- Report generation
- Easy-to-use navigation

**Menu Options:**
```
[1] Scan Network for Active Devices
[2] Capture Network Packets
[3] Analyze Traffic Patterns
[4] Detect Anomalies & Threats
[5] View All Results
[6] Generate Report
[7] Exit
```

### Option 2: Web Dashboard (Streamlit)

```bash
# First, ensure Streamlit is installed
pip install streamlit

# Run the web interface
streamlit run app_dashboard.py
```

**Features:**
- Modern web-based interface
- Real-time network monitoring
- Interactive charts and visualizations
- Download reports and data
- User-friendly threat alerts
- Tab-based navigation

**Available Modules:**
- Dashboard (Overview)
- Network Scanner
- Packet Capture
- Traffic Analysis
- Threat Detection
- Reports & Exports

### Option 3: Run Demo (No Admin Required)

#### Simple Demo (No External Dependencies)
```bash
python simple_demo.py
```

This demonstrates all features using sample data without requiring:
- Administrator privileges
- Network connections
- External packages (uses only Python standard library)

#### Full Demo (With Packages)
```bash
python demo.py
```

This provides a complete feature demonstration with detailed output.

## 🔑 Key Modules Explained

### network_scanner.py
```python
from network_scanner import NetworkScanner

scanner = NetworkScanner()
devices = scanner.scan_network("192.168.1.0/24")
scanner.save_results("scan_results.json")
```

**What it does:**
- Uses ARP protocol to discover active hosts
- Collects MAC addresses and attempts hostname resolution
- Outputs device information in structured format
- Saves results for later analysis

### packet_analyzer.py
```python
from packet_analyzer import PacketAnalyzer

analyzer = PacketAnalyzer()
analyzer.capture_packets(packet_count=100, timeout=60)
stats = analyzer.get_statistics()
```

**What it does:**
- Captures live network packets using Scapy
- Extracts detailed packet information
- Tracks protocol distribution (TCP/UDP/ICMP)
- Calculates bandwidth usage per IP
- Maintains packet statistics

### traffic_analyzer.py
```python
from traffic_analyzer import TrafficAnalyzer

analyzer = TrafficAnalyzer()
analyzer.load_packets(packets_list)
analysis = analyzer.analyze_traffic()
analyzer.print_analysis()
```

**What it does:**
- Analyzes protocol distribution
- Identifies top destination ports
- Tracks communication pairs (IP-to-IP)
- Calculates bandwidth consumption
- Generates insights and statistics

### anomaly_detector.py
```python
from anomaly_detector import AnomalyDetector

detector = AnomalyDetector()
alerts = detector.detect_anomalies(packets, ip_stats)
detector.print_alerts()
```

**What it does:**
- Detects port scanning attempts
- Identifies SYN flood attacks
- Catches ARP spoofing activity
- Flags bandwidth abuse
- Alerts on suspicious ports
- Generates severity-based alerts

## 📊 Output Files

All analysis generates JSON files for data persistence:

| File | Purpose |
|------|---------|
| `scan_results.json` | Network scan device list |
| `captured_packets.json` | Raw packet capture data |
| `traffic_analysis.json` | Traffic analysis results |
| `security_alerts.json` | Security alerts and threats |
| `network_monitoring_report_*.json` | Comprehensive reports |

## ⚠️ Important Requirements & Permissions

### Administrator/Root Privileges Required
Packet capture requires elevated system privileges:

**Windows:**
```powershell
# Run Command Prompt as Administrator, then:
python main.py
# Or use Streamlit
streamlit run app_dashboard.py
```

**Linux/macOS:**
```bash
# Use sudo for packet capture modules
sudo python3 main.py
sudo streamlit run app_dashboard.py
```

### Legal & Ethical Considerations
⚠️ **Important Reminders:**
- **Only monitor networks you own** or have explicit written permission
- **Unauthorized monitoring is illegal** in most jurisdictions
- This is an **educational tool** for learning purposes only
- Always **respect privacy laws** and data protection regulations
- Ensure compliance with **local cybersecurity regulations**

## 🎓 Learning Outcomes

By using this tool, you'll master:

✓ **Network Fundamentals**
- How devices communicate on networks
- OSI model and network protocols
- IP addressing and network ranges
- MAC addresses and ARP protocol

✓ **Network Monitoring**
- Live packet capture and analysis
- Traffic pattern recognition
- Bandwidth monitoring
- Device discovery and mapping

✓ **Cybersecurity**
- Threat detection and analysis
- Anomaly identification
- Attack pattern recognition
- Security alert generation
- Intrusion detection basics

✓ **Python Programming**
- Socket programming and networking
- Process automation
- Data analysis and visualization
- File I/O and data persistence
- Object-oriented design

✓ **Data Analysis**
- Statistical analysis of network data
- Data visualization
- Report generation
- JSON/CSV data handling

## 🛠️ Customization & Configuration

### Adjusting Detection Thresholds

Edit `anomaly_detector.py`:

```python
self.threshold_settings = {
    'high_port_count': 50,           # Ports to trigger alert
    'syn_flood_threshold': 100,      # SYN packets threshold
    'bandwidth_threshold': 100,      # MB threshold
    'arp_broadcast_threshold': 50    # ARP packets threshold
}
```

### Customizing Suspicious Ports

Edit the `_detect_unusual_ports` method:

```python
suspicious_ports = {23, 135, 139, 445, 21}  # Add/remove as needed
```

## 🐛 Troubleshooting

### Issue: "Permission Denied" or Admin Error
**Solution:** Run with administrative privileges
```bash
# Windows: Run Command Prompt as Administrator
# Linux: Use sudo
sudo python3 main.py
```

### Issue: Scapy Not Installed
**Solution:** Install the Scapy package
```bash
pip install scapy
```

### Issue: Network Interface Not Found
**Solution:** Specify network interface explicitly
- Windows: Look for Ethernet or Wi-Fi adapters
- Linux: Use `ifconfig` to find your interface

### Issue: Large PCAP Files
**Solution:** Reduce packet capture count or use time limits
- Reduce `packet_count` parameter
- Decrease `timeout` value
- Filter specific protocols

### Issue: False Positives in Alerts
**Solution:** Adjust thresholds in `anomaly_detector.py`
- Increase thresholds for less sensitivity
- Decrease for more sensitivity
- Add whitelisted IPs

## 📚 Educational Resources

### Learning Materials
- **Network Basics**: https://www.cisco.com/learning/
- **Scapy Documentation**: https://scapy.readthedocs.io/
- **Wireshark Guide**: https://www.wireshark.org/
- **Nmap Tutorial**: https://nmap.org/docs.html
- **Python Networking**: https://docs.python.org/3/library/socket.html

### Practice Ideas
1. Analyze your home network traffic
2. Identify devices connected to your network
3. Monitor bandwidth usage patterns
4. Create custom threat detection rules
5. Build automated response mechanisms
6. Integrate with external logging systems

## 🚀 Advanced Features (Future Enhancements)

Potential improvements for extending the tool:
- Machine learning for anomaly detection
- Database integration (SQLite/PostgreSQL)
- Real-time email/SMS alerts
- Network topology mapping
- Geographical IP visualization
- Custom rule builder
- Integration with Nmap and Wireshark
- Multi-threaded packet processing
- REST API for remote monitoring

## 📅 Project Timeline

**Recommended Learning Schedule:**

| Week | Tasks |
|------|-------|
| 1-2 | Setup environment, understand networks |
| 3-4 | Network scanning and device discovery |
| 5-6 | Packet capture and protocol analysis |
| 7-8 | Traffic analysis and pattern recognition |
| 9 | Anomaly detection implementation |
| 10 | Dashboard, reporting, optimization |

## 📝 Sample Workflow

```
1. Start Tool
   ↓
2. Scan Network → Discover Devices
   ↓
3. Capture Packets → Analyze Traffic
   ↓
4. Detect Anomalies → Generate Alerts
   ↓
5. Generate Reports → Export Data
   ↓
6. Review Findings → Plan Actions
```

## 🎯 Use Cases

**Home Network Monitoring:**
- Monitor connected devices
- Detect unauthorized access
- Track bandwidth usage
- Identify security issues

**Educational Learning:**
- Understand network fundamentals
- Learn cybersecurity concepts
- Practice threat detection
- Develop security skills

**Small Business:**
- Monitor network health
- Detect security threats
- Track bandwidth usage
- Generate compliance reports

## 📞 Support & Help

**If you encounter issues:**

1. Check the demo output: `python simple_demo.py`
2. Review code comments in each module
3. Verify admin privileges
4. Check network connectivity
5. Review system requirements
6. Consult README sections

## 📄 License & Attribution

This project is for **educational purposes only**.

Use it to learn and understand:
- Network security concepts
- Cybersecurity tools and techniques
- Python programming
- Network administration

## 🎓 Career Path Preparation

This project prepares you for:

✓ **Network Security Engineer**
- Monitor and secure networks
- Implement security protocols
- Respond to threats

✓ **SOC Analyst** (Security Operations Center)
- Analyze security logs
- Detect threats in real-time
- Escalate incidents

✓ **Penetration Tester**
- Identify network vulnerabilities
- Test security measures
- Report findings

✓ **Network Administrator**
- Manage network infrastructure
- Monitor network health
- Optimize performance

✓ **Cybersecurity Analyst**
- Analyze security data
- Create threat intelligence
- Develop detection rules

## 🙏 Acknowledgments

This tool is built using:
- **Python 3** - Programming language
- **Scapy** - Packet manipulation
- **Streamlit** - Web interface
- **Pandas** - Data analysis
- **Plotly** - Visualization

## ⭐ Key Takeaways

By completing this project, you will:

✨ Understand how networks actually work
✨ Learn practical cybersecurity skills
✨ Gain hands-on experience with security tools
✨ Develop real-world security awareness
✨ Build a portfolio project
✨ Prepare for cybersecurity careers

---

## 🚀 Ready to Start?

### Quick Start:

1. **Install Python** (if not already installed)
2. **Install dependencies**: `pip install -r requirements.txt`
3. **Run the tool**: `python main.py`
4. **Or try the web version**: `streamlit run app_dashboard.py`
5. **Or see a demo**: `python simple_demo.py`

### Questions or Issues?

- Check the README sections
- Review code comments
- Run the demo for examples
- Verify system requirements
- Check admin privileges for packet capture

---

**Happy Learning! 🔒🔍📊**

Remember: Security is everyone's responsibility. Use this knowledge ethically and legally!

Last Updated: January 2026
Version: 1.0
