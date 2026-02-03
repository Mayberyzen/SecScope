# SecOps 🔐

SecOps is a desktop-based **Security Operations (SOC) utility** built using **Python & PyQt6**.  
It provides real-time network visibility, risk-based connection analysis, and supporting security tools through a unified GUI.

This project is designed for **educational, defensive security, and SOC simulation purposes**.


### 🖧 Network Monitor
- Live monitoring of active network connections
- Packet capture and inspection
- Risk-based classification (**High / Medium / Low**)
- Auto-scrolling live tables
- Visual risk indicators
- Connection & packet logs
- CSV export support

### 🧪 Pentest Tools
- Ping
- Traceroute
- Port scanning
- Banner grabbing
- Subdomain enumeration
- Directory brute-forcing (basic)

### 📁 File & URL Analyzer
- File hash calculation
- URL inspection
- Basic threat indicators

### 🖥 System Health
- CPU usage
- Memory usage
- Disk usage
- Process monitoring

---

## 🧠 Risk Classification Logic

Connections and packets are categorized based on internal risk scoring rules:

| Risk Level | Description |
|-----------|------------|
| **LOW** | Normal or trusted activity |
| **MED** | Suspicious but non-critical |
| **HIGH** | Potentially malicious or dangerous |

High-risk events are visually emphasized and logged for rapid detection.

---

## 🛠 Installation

### Requirements
- Python **3.10+**
- Windows (Linux partially supported)
- **Administrator privileges** required for packet sniffing

### Setup

```bash
git clone https://github.com/YOUR_USERNAME/SecScope.git
cd SecScope
pip install -r requirements.txt
python main.py
