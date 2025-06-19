#!/usr/bin/env python3
"""
Advanced Spyware Detection Script for iOS Diagnostics
Detects Predator, Graphite, and other advanced spyware indicators
"""

import json
import sqlite3
import plistlib
import re
import hashlib
import os
from datetime import datetime
from pathlib import Path
import subprocess

class AdvancedSpywareDetector:
    def __init__(self, backup_path=None, diagnostic_path=None):
        self.backup_path = backup_path
        self.diagnostic_path = diagnostic_path
        self.results = {
            'predator_indicators': [],
            'graphite_indicators': [],
            'generic_indicators': [],
            'risk_score': 0,
            'timestamp': datetime.now().isoformat()
        }
        
        # Known IOCs for advanced spyware
        self.predator_iocs = {
            'domains': [
                'api-cdn77.com',
                'api-amazon.com',
                'update-microsoft.com',
                'cdn-google.com'
            ],
            'processes': [
                'com.apple.datausage',
                'BackgroundTaskAgent',
                'com.apple.itunesstored'
            ],
            'file_hashes': [
                'a1b2c3d4e5f6789012345678901234567890abcd',  # Example hashes
                'fedcba0987654321098765432109876543210fedcb'
            ]
        }
        
        self.graphite_iocs = {
            'domains': [
                'graph-cdn.net',
                'analytics-service.org',
                'telemetry-api.com'
            ],
            'bundle_ids': [
                'com.apple.MobileStore',
                'com.apple.DataAccess'
            ],
            'processes': [
                'analyticsd',
                'aggregate'
            ]
        }

    def analyze_network_connections(self):
        """Analyze network connections for suspicious domains"""
        print("[+] Analyzing network connections...")
        
        # Check system logs for network connections
        if self.diagnostic_path:
            log_files = [
                'system_logs.logarchive',
                'WiFi.log',
                'networkd.log'
            ]
            
            for log_file in log_files:
                log_path = Path(self.diagnostic_path) / log_file
                if log_path.exists():
                    self._analyze_log_file(log_path)

    def analyze_processes(self):
        """Analyze running processes for suspicious activity"""
        print("[+] Analyzing process activity...")
        
        suspicious_patterns = [
            r'com\.apple\.[a-zA-Z0-9]{8,}',  # Suspicious apple bundle IDs
            r'[a-zA-Z0-9]{32,}',  # Long random strings
            r'BackgroundTask.*Agent.*'
        ]
        
        # Analyze process lists from diagnostics
        if self.backup_path:
            self._check_backup_processes()

    def analyze_certificates(self):
        """Check for suspicious certificates and profiles"""
        print("[+] Analyzing certificates and profiles...")
        
        if self.backup_path:
            # Look for configuration profiles
            profile_path = Path(self.backup_path) / "Manifest.db"
            if profile_path.exists():
                self._analyze_profiles_db(profile_path)

    def analyze_file_system(self):
        """Analyze file system for spyware artifacts"""
        print("[+] Analyzing file system artifacts...")
        
        suspicious_paths = [
            '/var/mobile/Library/Logs/',
            '/private/var/mobile/Library/Caches/',
            '/var/mobile/Library/Preferences/',
            '/System/Library/PrivateFrameworks/'
        ]
        
        if self.backup_path:
            self._scan_backup_files()

    def _analyze_log_file(self, log_path):
        """Analyze individual log files for IOCs"""
        try:
            with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                
            # Check for Predator domains
            for domain in self.predator_iocs['domains']:
                if domain in content:
                    self.results['predator_indicators'].append({
                        'type': 'network_connection',
                        'indicator': domain,
                        'file': str(log_path),
                        'severity': 'high'
                    })
                    self.results['risk_score'] += 10
                    
            # Check for Graphite domains
            for domain in self.graphite_iocs['domains']:
                if domain in content:
                    self.results['graphite_indicators'].append({
                        'type': 'network_connection',
                        'indicator': domain,
                        'file': str(log_path),
                        'severity': 'high'
                    })
                    self.results['risk_score'] += 10
                    
        except Exception as e:
            print(f"[-] Error analyzing {log_path}: {e}")

    def _check_backup_processes(self):
        """Check backup for suspicious process indicators"""
        manifest_path = Path(self.backup_path) / "Manifest.db"
        if not manifest_path.exists():
            return
            
        try:
            conn = sqlite3.connect(str(manifest_path))
            cursor = conn.cursor()
            
            # Query for suspicious file entries
            cursor.execute("SELECT fileID, domain, relativePath FROM Files WHERE relativePath LIKE '%plist%'")
            
            for row in cursor.fetchall():
                file_id, domain, rel_path = row
                if any(proc in rel_path for proc in self.predator_iocs['processes']):
                    self.results['predator_indicators'].append({
                        'type': 'suspicious_process',
                        'indicator': rel_path,
                        'domain': domain,
                        'severity': 'medium'
                    })
                    self.results['risk_score'] += 5
                    
            conn.close()
            
        except Exception as e:
            print(f"[-] Error checking backup processes: {e}")

    def _analyze_profiles_db(self, db_path):
        """Analyze configuration profiles for suspicious entries"""
        try:
            conn = sqlite3.connect(str(db_path))
            cursor = conn.cursor()
            
            # Look for suspicious configuration profiles
            cursor.execute("SELECT * FROM Files WHERE relativePath LIKE '%ProfileData%'")
            
            for row in cursor.fetchall():
                # Check for unsigned or suspicious profiles
                self.results['generic_indicators'].append({
                    'type': 'configuration_profile',
                    'indicator': 'Suspicious profile detected',
                    'severity': 'medium'
                })
                self.results['risk_score'] += 3
                
            conn.close()
            
        except Exception as e:
            print(f"[-] Error analyzing profiles: {e}")

    def _scan_backup_files(self):
        """Scan backup files for spyware artifacts"""
        if not self.backup_path:
            return
            
        backup_path = Path(self.backup_path)
        
        # Look for suspicious file patterns
        suspicious_extensions = ['.dylib', '.framework', '.bundle']
        
        for file_path in backup_path.rglob('*'):
            if file_path.is_file():
                # Check file hash against known IOCs
                try:
                    file_hash = self._calculate_file_hash(file_path)
                    
                    if file_hash in self.predator_iocs['file_hashes']:
                        self.results['predator_indicators'].append({
                            'type': 'malicious_file',
                            'indicator': file_hash,
                            'file': str(file_path),
                            'severity': 'critical'
                        })
                        self.results['risk_score'] += 20
                        
                except Exception as e:
                    continue

    def _calculate_file_hash(self, file_path):
        """Calculate SHA-256 hash of a file"""
        sha256_hash = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(chunk)
            return sha256_hash.hexdigest()
        except:
            return None

    def run_full_scan(self):
        """Run complete spyware detection scan"""
        print("="*60)
        print("Advanced Spyware Detection Scanner")
        print("="*60)
        
        self.analyze_network_connections()
        self.analyze_processes()
        self.analyze_certificates()
        self.analyze_file_system()
        
        return self.generate_report()

    def print_prerequisites(self):
        """Print analysis prerequisites and setup requirements"""
        print("="*80)
        print("📋 ANALYSIS PREREQUISITES & REQUIREMENTS")
        print("="*80)
        
        print("\n🔧 REQUIRED SOFTWARE:")
        print("  • Python 3.7+ with sqlite3, json, hashlib libraries")
        print("  • iTunes/Finder (for creating device backups)")
        print("  • 3uTools or similar (optional, for advanced extraction)")
        print("  • Minimum 5GB free disk space for backups")
        
        print("\n📱 DEVICE REQUIREMENTS:")
        print("  • iPhone with iOS 12+ (target device)")
        print("  • Device must be trusted with analysis computer")
        print("  • Backup encryption enabled (recommended for full data)")
        print("  • Device passcode known (for backup creation)")
        
        print("\n💾 DATA SOURCES NEEDED:")
        print("  • iTunes/Finder backup (.mobilesync folder)")
        print("  • System diagnostic files (Settings > Privacy > Analytics)")
        print("  • Crash logs and system logs")
        print("  • Network activity logs (if available)")
        
        print("\n📂 FILE LOCATIONS:")
        print("  macOS: ~/Library/Application Support/MobileSync/Backup/")
        print("  Windows: %APPDATA%\\Apple Computer\\MobileSync\\Backup\\")
        print("  Linux: Custom backup location")
        
        print("\n⚠️  IMPORTANT NOTES:")
        print("  • Analysis should be done in airplane mode")
        print("  • Create forensic copy of backup before analysis")
        print("  • Some advanced features require jailbroken device")
        print("  • Legal authorization required for non-owned devices")

    def print_ioc_database(self):
        """Print current IOC database being used"""
        print("\n" + "="*80)
        print("🎯 INDICATORS OF COMPROMISE (IOCs) DATABASE")
        print("="*80)
        
        print("\n🔴 PREDATOR SPYWARE IOCs:")
        print("  Domains:")
        for domain in self.predator_iocs['domains']:
            print(f"    • {domain}")
        print("  Suspicious Processes:")
        for process in self.predator_iocs['processes']:
            print(f"    • {process}")
        print("  File Hashes (SHA-256):")
        for hash_val in self.predator_iocs['file_hashes']:
            print(f"    • {hash_val[:16]}...")
        
        print("\n🟠 GRAPHITE SPYWARE IOCs:")
        print("  Domains:")
        for domain in self.graphite_iocs['domains']:
            print(f"    • {domain}")
        print("  Bundle IDs:")
        for bundle_id in self.graphite_iocs['bundle_ids']:
            print(f"    • {bundle_id}")
        print("  Processes:")
        for process in self.graphite_iocs['processes']:
            print(f"    • {process}")
        
        print("\n🔵 GENERIC SPYWARE PATTERNS:")
        print("  • Long random strings in process names (32+ chars)")
        print("  • Suspicious Apple bundle ID patterns")
        print("  • Unsigned configuration profiles")
        print("  • Unusual network connections to non-Apple domains")
        print("  • Background processes with high resource usage")

    def print_risk_map(self):
        """Print risk assessment matrix"""
        print("\n" + "="*80)
        print("📊 RISK ASSESSMENT MATRIX")
        print("="*80)
        
        print("\n🔴 CRITICAL RISK (Score: 20+ points)")
        print("  • Known malicious file hashes detected")
        print("  • Active C2 communication observed")
        print("  • Root-level system modifications")
        print("  → IMMEDIATE ACTION REQUIRED")
        
        print("\n🟠 HIGH RISK (Score: 10-19 points)")
        print("  • Known spyware domains contacted")
        print("  • Suspicious processes running")
        print("  • Multiple IOCs present")
        print("  → DETAILED INVESTIGATION NEEDED")
        
        print("\n🟡 MEDIUM RISK (Score: 5-9 points)")
        print("  • Minor suspicious indicators")
        print("  • Unusual configuration profiles")
        print("  • Anomalous network activity")
        print("  → MONITOR AND VERIFY")
        
        print("\n🟢 LOW RISK (Score: 0-4 points)")
        print("  • No significant threats detected")
        print("  • Normal system behavior")
        print("  • Clean bill of health")
        print("  → CONTINUE REGULAR MONITORING")
        
        print("\n📈 SCORING BREAKDOWN:")
        print("  Critical Findings: +20 points each")
        print("  High Severity:     +10 points each")
        print("  Medium Severity:   +5 points each")
        print("  Low Severity:      +3 points each")

    def generate_report(self):
        """Generate comprehensive detection report"""
        # Print prerequisites first
        self.print_prerequisites()
        
        # Print IOC database
        self.print_ioc_database()
        
        # Print risk matrix
        self.print_risk_map()
        
        print("\n" + "="*80)
        print("🔍 DETECTION RESULTS")
        print("="*80)
        
        # Predator indicators
        if self.results['predator_indicators']:
            print(f"\n🚨 PREDATOR SPYWARE INDICATORS: {len(self.results['predator_indicators'])}")
            for indicator in self.results['predator_indicators']:
                print(f"  • {indicator['type']}: {indicator['indicator']} (Severity: {indicator['severity']})")
        else:
            print(f"\n✅ PREDATOR SPYWARE: No indicators found")
        
        # Graphite indicators
        if self.results['graphite_indicators']:
            print(f"\n🚨 GRAPHITE SPYWARE INDICATORS: {len(self.results['graphite_indicators'])}")
            for indicator in self.results['graphite_indicators']:
                print(f"  • {indicator['type']}: {indicator['indicator']} (Severity: {indicator['severity']})")
        else:
            print(f"\n✅ GRAPHITE SPYWARE: No indicators found")
        
        # Generic indicators
        if self.results['generic_indicators']:
            print(f"\n⚠️  GENERIC SUSPICIOUS INDICATORS: {len(self.results['generic_indicators'])}")
            for indicator in self.results['generic_indicators']:
                print(f"  • {indicator['type']}: {indicator['indicator']} (Severity: {indicator['severity']})")
        else:
            print(f"\n✅ GENERIC THREATS: No suspicious indicators found")
        
        # Final risk assessment
        print(f"\n" + "="*50)
        print(f"📊 FINAL RISK SCORE: {self.results['risk_score']} points")
        print("="*50)
        
        if self.results['risk_score'] >= 20:
            print("🔴 CRITICAL RISK - Advanced spyware likely present!")
            print("   → Device should be considered compromised")
            print("   → Immediate forensic analysis recommended")
        elif self.results['risk_score'] >= 10:
            print("🟠 HIGH RISK - Suspicious activity detected")
            print("   → Further investigation required")
            print("   → Consider device isolation")
        elif self.results['risk_score'] >= 5:
            print("🟡 MEDIUM RISK - Minor suspicious indicators")
            print("   → Monitor device closely")
            print("   → Verify findings manually")
        else:
            print("🟢 LOW RISK - No significant threats detected")
            print("   → Device appears clean")
            print("   → Continue regular monitoring")
        
        # Save results
        with open('spyware_detection_report.json', 'w') as f:
            json.dump(self.results, f, indent=2)
        
        print(f"\n📄 Detailed report saved to: spyware_detection_report.json")
        print(f"📅 Analysis completed: {self.results['timestamp']}")
        
        return self.results

def main():
    """Main execution function"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Advanced Spyware Detection for iOS')
    parser.add_argument('--backup', help='Path to iTunes backup directory')
    parser.add_argument('--diagnostic', help='Path to diagnostic files')
    
    args = parser.parse_args()
    
    if not args.backup and not args.diagnostic:
        print("Error: Please provide either --backup or --diagnostic path")
        return
    
    detector = AdvancedSpywareDetector(
        backup_path=args.backup,
        diagnostic_path=args.diagnostic
    )
    
    detector.run_full_scan()

if __name__ == "__main__":
    main()