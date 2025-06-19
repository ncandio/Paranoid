# Paranoid
# iOS Advanced Spyware Detection Tool

**⚠️ IMPORTANT: This tool is specifically designed for iOS devices only. It does not work with Android devices.**

An automated detection script for advanced spyware including Predator, Graphite, and other commercial surveillance tools targeting iOS devices.

## 🎯 What This Tool Detects

- **Predator Spyware**: Commercial spyware sold to governments and law enforcement
- **Graphite Spyware**: Advanced persistent threat targeting mobile devices
- **Generic Spyware**: Other surveillance tools and malicious software
- **System Compromises**: Jailbreaks, unauthorized profiles, suspicious processes

## 📋 Windows Prerequisites

### Hardware Requirements
- **USB Cable**: Original Apple Lightning/USB-C cable (third-party cables may not work reliably)
- **Storage**: Minimum 10GB free disk space for backups and analysis
- **RAM**: At least 4GB RAM recommended
- **Processor**: Any modern Windows PC (Windows 10/11 recommended)

### Software Installation (Step by Step)

#### 1. Install Python 3.7+
```
1. Download Python from: https://www.python.org/downloads/windows/
2. Download the latest Python 3.x version (3.11+ recommended)
3. During installation, CHECK "Add Python to PATH" option
4. Click "Install Now"
5. Verify installation: Open Command Prompt and type: python --version
```

#### 2. Install iTunes (Required for iOS Backups)
```
Option A - Microsoft Store (Recommended):
1. Open Microsoft Store
2. Search for "iTunes"
3. Install iTunes from Apple Inc.

Option B - Apple Website:
1. Go to: https://www.apple.com/itunes/download/
2. Download iTunes for Windows
3. Install following the setup wizard
```

#### 3. Download the Detection Script
```
1. Download the spyware_detector.py file
2. Save it to a folder like: C:\SpywareDetection\
3. Open Command Prompt as Administrator
4. Navigate to the folder: cd C:\SpywareDetection\
```

## 📱 iOS Device Preparation

### Supported Devices
- **iPhone**: All models with iOS 12.0 or later
- **iPad**: All models with iPadOS 13.0 or later
- **iPod Touch**: 7th generation with iOS 12.0 or later

### Device Setup Steps
1. **Connect iPhone to PC** using original Apple cable
2. **Trust the Computer**:
   - When prompted on iPhone, tap "Trust"
   - Enter your iPhone passcode
3. **Enable Backup Encryption** (Critical for full analysis):
   - Open iTunes
   - Select your device
   - Check "Encrypt local backup"
   - Set a backup password (remember this!)
4. **Put Device in Airplane Mode** (recommended during analysis)

## 🔧 Creating iTunes Backup

### Method 1: Using iTunes
```
1. Open iTunes
2. Connect iPhone with cable
3. Click on iPhone icon in iTunes
4. Under "Backups" section:
   - Select "This computer"
   - Check "Encrypt local backup"
   - Click "Back Up Now"
5. Wait for backup completion (10-30 minutes)
```

### Method 2: Using Command Line
```
# Open Command Prompt as Administrator
cd "%APPDATA%\Apple Computer\MobileSync\Backup"
dir
# Note the folder name (this is your backup ID)
```

## 🚀 Running the Analysis

### Basic Usage
```bash
# Navigate to script folder
cd C:\SpywareDetection\

# Run analysis on iTunes backup
python spyware_detector.py --backup "%APPDATA%\Apple Computer\MobileSync\Backup\[BACKUP-ID]"

# Example with actual backup ID
python spyware_detector.py --backup "%APPDATA%\Apple Computer\MobileSync\Backup\12345678-90ab-cdef-1234-567890abcdef"
```

### Finding Your Backup Location
```bash
# List all backups
dir "%APPDATA%\Apple Computer\MobileSync\Backup"

# Each folder represents one device backup
# Use the most recent folder for your target device
```

### Advanced Usage with Diagnostic Files
```bash
# If you have diagnostic files from iPhone
python spyware_detector.py --backup "[BACKUP-PATH]" --diagnostic "[DIAGNOSTIC-PATH]"
```

## 📊 Understanding Results

### Risk Levels
- **🔴 CRITICAL (20+ points)**: Device likely compromised, immediate action required
- **🟠 HIGH (10-19 points)**: Suspicious activity detected, investigate further
- **🟡 MEDIUM (5-9 points)**: Minor indicators, monitor device
- **🟢 LOW (0-4 points)**: Clean device, no threats detected

### Output Files
- **Console Output**: Real-time analysis results
- **spyware_detection_report.json**: Detailed technical report
- **Backup Files**: Preserved in original location

## 🔍 What the Tool Analyzes

### Data Sources
- **iTunes Backup Files**: Complete device backup
- **System Logs**: iOS system and application logs
- **Network Connections**: Suspicious domain communications
- **Process Lists**: Running applications and services
- **Configuration Profiles**: Device management profiles
- **File Hashes**: Known malicious file signatures

### Detection Methods
- **IOC Matching**: Known Indicators of Compromise
- **Behavioral Analysis**: Suspicious system behavior
- **Network Analysis**: Malicious domain detection
- **File System Analysis**: Unauthorized file modifications

## ⚠️ Legal and Ethical Considerations

### Legal Requirements
- **Only analyze devices you own or have explicit written permission to analyze**
- **Corporate devices require IT department authorization**
- **Law enforcement use requires proper legal authority**
- **Unauthorized analysis may violate privacy laws**

### Best Practices
- **Isolate device during analysis** (airplane mode)
- **Create forensic backup copy** before analysis
- **Document all findings** for potential legal proceedings
- **Secure storage** of backup files (encrypted)

## 🛠️ Troubleshooting

### Common Issues

#### "Python is not recognized"
```
Solution: Reinstall Python and check "Add Python to PATH"
Verify: python --version in Command Prompt
```

#### "iTunes not detecting device"
```
Solutions:
1. Try different USB port
2. Use original Apple cable
3. Restart iTunes and iPhone
4. Update iTunes to latest version
5. Install Apple Mobile Device Support
```

#### "Backup failed" or "Backup corrupted"
```
Solutions:
1. Ensure sufficient disk space (10GB+)
2. Try without backup encryption first
3. Reset iPhone trust settings
4. Update iTunes and iOS
```

#### "Access denied" errors
```
Solutions:
1. Run Command Prompt as Administrator
2. Check backup folder permissions
3. Disable antivirus temporarily
4. Ensure iTunes is closed during analysis
```

### System Requirements Issues
```
Minimum Requirements:
- Windows 10/11 (64-bit recommended)
- 4GB RAM minimum, 8GB recommended
- 20GB free disk space
- USB 2.0 or higher port
```

## 📞 Support and Updates

### Getting Help
- **Check this README first** for common solutions
- **Verify all prerequisites** are properly installed
- **Test with a clean iTunes backup** first
- **Document error messages** for troubleshooting

### Updating IOCs
The tool uses built-in IOC databases, but you can update them by:
1. Downloading latest threat intelligence
2. Updating the IOC lists in the script
3. Adding new domains, hashes, or process names

### Version Information
- **Current Version**: 1.0
- **iOS Compatibility**: iOS 12.0 - iOS 17.x
- **Windows Compatibility**: Windows 10/11
- **Python Requirement**: 3.7+

## 🔒 Privacy and Security

### Data Handling
- **All analysis is performed locally** on your PC
- **No data is sent to external servers**
- **Backup files remain on your system**
- **Reports are saved locally only**

### Secure Practices
- **Encrypt backup files** with strong passwords
- **Store backups securely** (encrypted drive)
- **Delete temporary files** after analysis
- **Use offline analysis** when possible

---

**⚠️ DISCLAIMER**: This tool is for authorized security analysis only. Users are responsible for ensuring they have proper authorization before analyzing any device. Unauthorized access to devices may violate local, state, and federal laws.
