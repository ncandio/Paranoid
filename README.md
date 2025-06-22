# Paranoid

## Advanced iOS Spyware Detection Toolkit for Windows

![Paranoid - iOS Spyware Detector](./images/paranoid_logo.png)

**⚠️ IMPORTANT: This tool is designed specifically for iOS devices and does not support Android.**

Paranoid is a comprehensive security toolkit that automatically detects advanced spyware including Predator, Graphite, Pegasus, and other commercial surveillance tools targeting iOS devices. Built for forensic analysis of iOS backups, Paranoid helps you verify if your device has been compromised.

## 🔍 Detection Capabilities

Paranoid is engineered to detect the following threats:

### Commercial Surveillance Tools
- **Predator Spyware**: Advanced commercial surveillance tool sold to government entities
- **Graphite Spyware**: Sophisticated persistent threat targeting iOS devices
- **Pegasus Spyware**: NSO Group's zero-click surveillance platform

### Remote Access Trojans (RATs)
- **NJRat**: Remote access trojan with advanced persistence capabilities
- **Remcos**: Sophisticated remote control and surveillance software
- **AsyncRAT**: Stealthy remote administration tool used in targeted attacks
- **DarkGate RAT**: Multi-functional remote access trojan with evasion capabilities

### Mobile Banking Threats
- **Anubis**: Advanced banking trojan and keylogger targeting mobile devices

### System Compromise Indicators
- **Jailbreak Artifacts**: Detection of system-level modifications
- **Unauthorized Profiles**: Identification of potentially malicious configuration profiles
- **Suspicious Processes**: Detection of unusual background processes
- **Network Anomalies**: Identification of communications with known C2 servers

## 🛠️ Technical Features

- **Complete File System Analysis**: Scans iTunes backup files for malicious artifacts
- **Network Traffic Examination**: Identifies connections to known C2 domains
- **Process Analysis**: Detects suspicious processes and services
- **Configuration Profile Verification**: Identifies unauthorized MDM profiles
- **Hash-Based Detection**: Compares file hashes against known malicious signatures
- **Forensic Reporting**: Generates comprehensive JSON reports for further analysis

## 📋 System Requirements

### Hardware Requirements
- **Processor**: Any modern x86/x64 CPU (2GHz+ recommended)
- **RAM**: Minimum 4GB (8GB+ recommended)
- **Storage**: 10GB+ free space for backup analysis
- **Connectivity**: USB port with original Apple cable

### Software Prerequisites
- **Operating System**: Windows 10/11 (64-bit recommended)
- **Python**: Version 3.7 or higher
- **iTunes**: Latest version with Apple Mobile Device Support
- **Visual C++ Redistributable**: 2015+ Runtime

## 🚀 Installation

### Automated Installation
```bash
# Clone the repository
git clone https://github.com/yourusername/paranoid.git
cd paranoid

# Install dependencies
pip install -r requirements.txt
```

### Manual Setup
1. **Install Python 3.7+**
   - Download from [python.org](https://www.python.org/downloads/windows/)
   - Check "Add Python to PATH" during installation

2. **Install iTunes**
   - Download from [Apple's website](https://www.apple.com/itunes/download/)
   - Ensure "Apple Mobile Device Support" is installed

3. **Download Paranoid**
   - Download the latest release from our repository
   - Extract to a folder (e.g., `C:\Paranoid`)

## 📱 Usage Guide

### Basic Usage
```bash
# Run analysis on an iTunes backup
python spyware_detector.py --backup "%APPDATA%\Apple Computer\MobileSync\Backup\[BACKUP-ID]"

# Advanced analysis with diagnostic logs
python spyware_detector.py --backup "[BACKUP-PATH]" --diagnostic "[DIAGNOSTIC-PATH]"
```

### Creating an iTunes Backup
1. Connect your iPhone to your computer
2. Open iTunes and select your device
3. Choose "Back up to this computer"
4. Enable "Encrypt local backup" for full access
5. Click "Back Up Now" and wait for completion

### Locating Your Backup
```bash
# List all backups
dir "%APPDATA%\Apple Computer\MobileSync\Backup"
```

## 📊 Understanding Results

### Risk Assessment Scale
- **🔴 CRITICAL (20+ points)**: Device is likely compromised
- **🟠 HIGH (10-19 points)**: Suspicious indicators detected
- **🟡 MEDIUM (5-9 points)**: Minor anomalies present
- **🟢 LOW (0-4 points)**: No significant threats detected

### Detection Methodology
- **IOC Matching**: Comparison against known Indicators of Compromise
- **Behavioral Analysis**: Identification of abnormal system behavior
- **Heuristic Scanning**: Detection of suspicious patterns
- **Forensic Analysis**: In-depth examination of system artifacts

## 🔒 Security Considerations

### Data Protection
- **Local Analysis**: All scanning is performed locally on your computer
- **No Data Transmission**: No data is sent to external servers
- **Secure Reporting**: Reports are saved locally with optional encryption

### Legal Compliance
- **Authorization Required**: Only scan devices you own or have explicit permission to analyze
- **Corporate Policy**: Business devices may require IT department approval
- **Privacy Laws**: Respect applicable privacy and data protection regulations

## 🧰 Advanced Features

### Focused Spyware Detection
For targeted Pegasus spyware detection only:
```bash
python AdvancedSpywareDetector.py --backup "[BACKUP-PATH]"
```

### Command Line Options
```
--backup        Path to iTunes backup directory
--diagnostic    Path to iOS diagnostic files
--report        Custom path for report output
--quiet         Suppress console output (results still saved to file)
--json-only     Output only JSON data (for programmatic use)
```

## 📚 Troubleshooting

### Common Issues

#### Backup Access Problems
```
- Ensure iTunes is closed during analysis
- Check backup encryption password is correct
- Verify backup location exists
```

#### Python Errors
```
- Verify Python 3.7+ is installed: python --version
- Check all dependencies are installed: pip install -r requirements.txt
- Run as Administrator if needed for full system access
```

## 🛡️ Disclaimer

This tool is for legitimate security analysis only. Users are responsible for ensuring they have proper authorization before analyzing any device. Unauthorized access to devices may violate applicable laws.

---

## 📞 Support and Updates

- **GitHub**: [Report issues](https://github.com/yourusername/paranoid/issues)
- **Documentation**: [Full documentation](https://github.com/yourusername/paranoid/wiki)
- **Updates**: Check for new IOC databases monthly

**Version**: 1.1.0
**Last Updated**: June 2024
