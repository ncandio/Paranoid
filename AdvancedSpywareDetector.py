#!/usr/bin/env python3
"""
Advanced Spyware Detection for iOS: Example Implementation
A tool to detect and analyze NSO Pegasus spyware indicators on iOS devices
"""

import os
import sys
import json
import hashlib
import sqlite3
import argparse
from datetime import datetime
from pathlib import Path

class AdvancedPegasusDetector:
    def __init__(self, ios_backup_path=None, diagnostic_path=None):
        self.backup_path = ios_backup_path
        self.diagnostic_path = diagnostic_path
        self.timestamp = datetime.now().isoformat()
        self.results = {
            'pegasus_indicators': [],
            'risk_score': 0,
            'timestamp': self.timestamp
        }
        
        # Pegasus IOCs - these are examples and should be updated with actual IOCs
        self.pegasus_iocs = {
            'domains': [
                'nso-update.com',
                'pegasus-cdn.net',
                'bh-cdn.com',
                'cdn-push-service.com',
                'appleservice.net',
                'nsogroup-updates.com'
            ],
            'processes': [
                'installd.service',
                'locationd.override',
                'com.apple.coretelephony.agent',
                'ctd.media',
                'com.apple.securityd.extension'
            ],
            'bundle_ids': [
                'com.apple.private.alloy',
                'com.apple.itunes.analytics',
                'com.apple.purplebuddy',
                'com.apple.securityd.wrapper'
            ],
            'file_paths': [
                '/private/var/db/analyzers/',
                '/private/var/mobile/Library/SMSNinja/',
                '/private/var/mobile/Library/Preferences/com.apple.locationd.plist',
                '/private/var/mobile/Library/Logs/CrashReporter/',
                '/System/Library/PrivateFrameworks/MediaServices.framework/'
            ],
            'file_hashes': [
                '7e6f0e86b5d1f43f9b917a3b92a97f5c75e462a9b50f2865e0fd52a5b7c79540',
                'c13bf5d18978e475d5631c800e5b3ca3c9cb3a31731f7d3947ee8375e59976a1',
                'a1fc382eeae0e0fb431c5c2e52889ebd52d9a8d0cf7c76e42a951908563c09fa'
            ]
        }
        
    def analyze_backup_files(self):
        """Analyze iOS backup files for Pegasus indicators"""
        print("[+] Analyzing backup files for Pegasus indicators...")
        
        if not self.backup_path or not os.path.exists(self.backup_path):
            print("[-] Backup path not found or not provided")
            return
            
        try:
            # Check Manifest.db for suspicious entries
            manifest_path = os.path.join(self.backup_path, "Manifest.db")
            if os.path.exists(manifest_path):
                self._analyze_manifest_db(manifest_path)
                
            # Scan for suspicious files
            self._scan_backup_for_suspicious_files()
            
        except Exception as e:
            print(f"[-] Error analyzing backup: {e}")
    
    def analyze_diagnostic_files(self):
        """Analyze iOS diagnostic files for Pegasus indicators"""
        print("[+] Analyzing diagnostic files for Pegasus indicators...")
        
        if not self.diagnostic_path or not os.path.exists(self.diagnostic_path):
            print("[-] Diagnostic path not found or not provided")
            return
            
        try:
            # Check for suspicious log entries
            self._analyze_log_files()
            
            # Check for suspicious system config
            self._analyze_system_config()
            
        except Exception as e:
            print(f"[-] Error analyzing diagnostics: {e}")
    
    def _analyze_manifest_db(self, db_path):
        """Analyze the backup Manifest.db for suspicious entries"""
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            # Look for suspicious file paths
            for file_path in self.pegasus_iocs['file_paths']:
                cursor.execute("SELECT fileID, domain, relativePath FROM Files WHERE relativePath LIKE ?", 
                              (f"%{file_path}%",))
                
                for row in cursor.fetchall():
                    file_id, domain, rel_path = row
                    self.results['pegasus_indicators'].append({
                        'type': 'suspicious_file_path',
                        'indicator': rel_path,
                        'domain': domain,
                        'severity': 'high'
                    })
                    self.results['risk_score'] += 8
            
            # Look for suspicious bundle IDs
            for bundle_id in self.pegasus_iocs['bundle_ids']:
                cursor.execute("SELECT fileID, domain, relativePath FROM Files WHERE domain LIKE ?", 
                              (f"%{bundle_id}%",))
                
                for row in cursor.fetchall():
                    file_id, domain, rel_path = row
                    self.results['pegasus_indicators'].append({
                        'type': 'suspicious_bundle_id',
                        'indicator': domain,
                        'file': rel_path,
                        'severity': 'critical'
                    })
                    self.results['risk_score'] += 15
            
            conn.close()
            
        except Exception as e:
            print(f"[-] Error analyzing Manifest.db: {e}")
    
    def _scan_backup_for_suspicious_files(self):
        """Scan backup files for suspicious hashes and content"""
        for root, dirs, files in os.walk(self.backup_path):
            for file in files:
                if file.endswith('.plist') or file.endswith('.db'):
                    file_path = os.path.join(root, file)
                    
                    # Check file hash
                    try:
                        file_hash = self._calculate_file_hash(file_path)
                        if file_hash in self.pegasus_iocs['file_hashes']:
                            self.results['pegasus_indicators'].append({
                                'type': 'malicious_file',
                                'indicator': file_hash,
                                'file': file_path,
                                'severity': 'critical'
                            })
                            self.results['risk_score'] += 20
                    except:
                        continue
    
    def _analyze_log_files(self):
        """Analyze diagnostic log files for suspicious entries"""
        if not self.diagnostic_path:
            return
            
        # Look for common log files
        log_files = [
            'syslog',
            'system.log',
            'WiFi.log',
            'CrashReporter',
            'mobilebackup.log'
        ]
        
        for log_file in log_files:
            for root, dirs, files in os.walk(self.diagnostic_path):
                if log_file in root or any(log_file in f for f in files):
                    self._check_log_for_iocs(os.path.join(root, log_file))
    
    def _check_log_for_iocs(self, log_path):
        """Check log files for IOCs"""
        if os.path.isfile(log_path):
            try:
                with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    
                    # Check for suspicious domains
                    for domain in self.pegasus_iocs['domains']:
                        if domain in content:
                            self.results['pegasus_indicators'].append({
                                'type': 'suspicious_domain',
                                'indicator': domain,
                                'file': log_path,
                                'severity': 'critical'
                            })
                            self.results['risk_score'] += 18
                    
                    # Check for suspicious processes
                    for process in self.pegasus_iocs['processes']:
                        if process in content:
                            self.results['pegasus_indicators'].append({
                                'type': 'suspicious_process',
                                'indicator': process,
                                'file': log_path,
                                'severity': 'high'
                            })
                            self.results['risk_score'] += 12
            except:
                pass
    
    def _analyze_system_config(self):
        """Analyze system configuration files for suspicious entries"""
        # This would analyze plist files, configuration profiles, etc.
        pass
    
    def _calculate_file_hash(self, file_path):
        """Calculate SHA-256 hash of a file"""
        sha256_hash = hashlib.sha256()
        
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256_hash.update(chunk)
                
        return sha256_hash.hexdigest()
    
    def generate_report(self):
        """Generate the final detection report"""
        print("\n" + "="*80)
        print("= PEGASUS DETECTION RESULTS")
        print("="*80)
        
        if self.results['pegasus_indicators']:
            print(f"\n=� PEGASUS SPYWARE INDICATORS: {len(self.results['pegasus_indicators'])}")
            
            # Group by severity
            critical = [i for i in self.results['pegasus_indicators'] if i['severity'] == 'critical']
            high = [i for i in self.results['pegasus_indicators'] if i['severity'] == 'high']
            medium = [i for i in self.results['pegasus_indicators'] if i['severity'] == 'medium']
            
            if critical:
                print("\n�  CRITICAL SEVERITY INDICATORS:")
                for indicator in critical:
                    print(f"  " {indicator['type']}: {indicator['indicator']} (File: {indicator.get('file', 'N/A')})")
            
            if high:
                print("\n�  HIGH SEVERITY INDICATORS:")
                for indicator in high:
                    print(f"  " {indicator['type']}: {indicator['indicator']} (File: {indicator.get('file', 'N/A')})")
            
            if medium:
                print("\n�  MEDIUM SEVERITY INDICATORS:")
                for indicator in medium:
                    print(f"  " {indicator['type']}: {indicator['indicator']} (File: {indicator.get('file', 'N/A')})")
        else:
            print(f"\n PEGASUS SPYWARE: No indicators found")
        
        # Final risk assessment
        print(f"\n" + "="*50)
        print(f"=� FINAL RISK SCORE: {self.results['risk_score']} points")
        print("="*50)
        
        if self.results['risk_score'] >= 30:
            print("=4 CRITICAL RISK - Pegasus spyware likely present!")
            print("   � Device should be considered compromised")
            print("   � Immediate forensic analysis recommended")
            print("   � Consider factory reset after data backup")
        elif self.results['risk_score'] >= 15:
            print("=� HIGH RISK - Suspicious activity detected")
            print("   � Further investigation required")
            print("   � Consider device isolation")
        elif self.results['risk_score'] >= 5:
            print("=� MEDIUM RISK - Minor suspicious indicators")
            print("   � Monitor device closely")
            print("   � Verify findings with further analysis")
        else:
            print("=� LOW RISK - No significant Pegasus indicators detected")
            print("   � Device appears clean of Pegasus spyware")
            print("   � Continue regular monitoring")
        
        # Save results to file
        report_path = "pegasus_detection_report.json"
        with open(report_path, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        print(f"\n=� Detailed report saved to: {report_path}")
        print(f"=� Analysis completed: {self.timestamp}")
        
        return self.results

def main():
    parser = argparse.ArgumentParser(description='Advanced Pegasus Spyware Detection for iOS')
    parser.add_argument('--backup', help='Path to iTunes backup directory')
    parser.add_argument('--diagnostic', help='Path to diagnostic files directory')
    parser.add_argument('--report', help='Custom path for report output')
    parser.add_argument('--quiet', action='store_true', help='Suppress console output (results still saved to file)')
    parser.add_argument('--json-only', action='store_true', help='Output only JSON data (for programmatic use)')
    parser.add_argument('--version', action='store_true', help='Display version information')
    
    args = parser.parse_args()
    
    # Version information
    if args.version:
        print("Paranoid - Advanced Pegasus Spyware Detection Tool")
        print("Version: 1.1.0")
        print("Last Updated: June 2024")
        print("Supports: iOS 12.0 - 17.x")
        return
    
    if not args.backup and not args.diagnostic:
        print("Error: Please provide either --backup or --diagnostic path")
        parser.print_help()
        return
    
    # Setup custom report path if specified
    report_path = args.report if args.report else 'pegasus_detection_report.json'
    
    # Configure quiet mode
    if args.quiet:
        # Redirect stdout to null
        import sys
        import os
        sys.stdout = open(os.devnull, 'w')
    
    detector = AdvancedPegasusDetector(
        ios_backup_path=args.backup,
        diagnostic_path=args.diagnostic
    )
    
    detector.analyze_backup_files()
    detector.analyze_diagnostic_files()
    results = detector.generate_report()
    
    # Restore stdout if needed
    if args.quiet:
        sys.stdout = sys.__stdout__
    
    # Save results to specified path
    import json
    with open(report_path, 'w') as f:
        json.dump(results, f, indent=2)
    
    # Print path to report file
    if not args.quiet:
        print(f"\n📄 Detailed report saved to: {report_path}")
        
    # For JSON-only mode, just print the JSON to stdout (useful for piping)
    if args.json_only:
        print(json.dumps(results, indent=2))

if __name__ == "__main__":
    main()