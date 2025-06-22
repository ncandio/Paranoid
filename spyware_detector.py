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
            'pegasus_indicators': [],
            'njrat_indicators': [],
            'remcos_indicators': [],
            'asyncrat_indicators': [],
            'darkgate_indicators': [],
            'anubis_indicators': [],
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
        
        self.pegasus_iocs = {
            'domains': [
                'nso-update.com',
                'pegasus-cdn.net',
                'bh-cdn.com',
                'cdn-push-service.com'
            ],
            'processes': [
                'installd.service',
                'locationd.override',
                'com.apple.coretelephony.agent'
            ],
            'bundle_ids': [
                'com.apple.private.alloy',
                'com.apple.itunes.analytics',
                'com.apple.purplebuddy'
            ],
            'file_hashes': [
                '7e6f0e86b5d1f43f9b917a3b92a97f5c75e462a9b50f2865e0fd52a5b7c79540',
                'c13bf5d18978e475d5631c800e5b3ca3c9cb3a31731f7d3947ee8375e59976a1'
            ]
        }
        
        self.njrat_iocs = {
            'domains': [
                'njrat-c2.net',
                'njrhost.ddns.net',
                'njrat-control.com',
                'njr4t.duckdns.org'
            ],
            'processes': [
                'wmiprv.exe',
                'svchost32.exe',
                'systemservices.exe',
                'rundll64.exe'
            ],
            'file_hashes': [
                'f1d903251db466d35533c28e3c032b7212aa43c0d6739a6ea5a8f9c342513282',
                '8b3c5384559a6a4612decb0a730dfa1ce1392dc5003d3f8c766c9c6e10e68b58'
            ]
        }
        
        self.remcos_iocs = {
            'domains': [
                'remcos-server.com',
                'remcos-panel.net',
                'remcos-c2.ddns.net',
                'rem-control.hopto.org'
            ],
            'processes': [
                'remcos.exe',
                'remcosagent.exe',
                'winupdate.exe',
                'msupdate.exe'
            ],
            'file_hashes': [
                '3e1a8e3d72f7632fd9b455a0b6ead4ff386c33f4e0d5f7a5b4e6d0f35658c5b8',
                'db3eb3a4a048c9e5fb6f2ea3d9a4d70fc87694d67fdff4da71574374b15a5730'
            ]
        }
        
        self.asyncrat_iocs = {
            'domains': [
                'asyncrat-c2.ddns.net',
                'async-panel.duckdns.org',
                'asynccontrol.net',
                'async-srv.hopto.org'
            ],
            'processes': [
                'asyncclient.exe',
                'asyncrat.exe',
                'clienttask.exe',
                'taskservice.exe'
            ],
            'file_hashes': [
                '0af9d81b9b8ed4b3c802068ef1d7b24a28c6ea97efd2c7797b3175d9e161a975',
                'b7c1a7f24ec0684eaae6f8c65982adcf75c1d5fd7d734853ddfbb8fb87405b7a'
            ]
        }
        
        self.darkgate_iocs = {
            'domains': [
                'darkgate-c2.com',
                'darkgate-panel.net',
                'darkgate.ddns.net',
                'dg-control.hopto.org'
            ],
            'processes': [
                'darkgate.exe',
                'dg_client.exe',
                'svcprocess.exe',
                'windowsupd.exe'
            ],
            'file_hashes': [
                'c98f307a3f78d956c1d42dc6c9f891a280ceac3f76b456a38992d567e95e68a4',
                '7e93752c5f1c9da26a5ab9c9db584c907e46508295fd5652b5b3e1db2c2fb0d4'
            ]
        }
        
        self.anubis_iocs = {
            'domains': [
                'anubis-c2.com',
                'anubiscontrol.net',
                'anubis-panel.ddns.net',
                'anubis-srv.duckdns.org'
            ],
            'processes': [
                'anubis.exe',
                'anubisd.exe',
                'anubisservice.exe',
                'securityservice.exe'
            ],
            'bundle_ids': [
                'com.security.anubis',
                'com.mobile.banking.anubis',
                'com.anubis.service'
            ],
            'file_hashes': [
                '5e84db69239eb46a5a3cf00ba530e517adc1912ede299b8d7ae434fef06d2faf',
                'e32b29c89fe01a2ef5eaa361ab0d6fe8e48a966afaea271e29ac8d3a10783b39'
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
                    
            # Check for Pegasus domains
            for domain in self.pegasus_iocs['domains']:
                if domain in content:
                    self.results['pegasus_indicators'].append({
                        'type': 'network_connection',
                        'indicator': domain,
                        'file': str(log_path),
                        'severity': 'critical'
                    })
                    self.results['risk_score'] += 20
                    
            # Check for NJRat domains
            for domain in self.njrat_iocs['domains']:
                if domain in content:
                    self.results['njrat_indicators'].append({
                        'type': 'network_connection',
                        'indicator': domain,
                        'file': str(log_path),
                        'severity': 'critical'
                    })
                    self.results['risk_score'] += 15
            
            # Check for Remcos domains
            for domain in self.remcos_iocs['domains']:
                if domain in content:
                    self.results['remcos_indicators'].append({
                        'type': 'network_connection',
                        'indicator': domain,
                        'file': str(log_path),
                        'severity': 'critical'
                    })
                    self.results['risk_score'] += 15
            
            # Check for AsyncRAT domains
            for domain in self.asyncrat_iocs['domains']:
                if domain in content:
                    self.results['asyncrat_indicators'].append({
                        'type': 'network_connection',
                        'indicator': domain,
                        'file': str(log_path),
                        'severity': 'critical'
                    })
                    self.results['risk_score'] += 15
            
            # Check for DarkGate domains
            for domain in self.darkgate_iocs['domains']:
                if domain in content:
                    self.results['darkgate_indicators'].append({
                        'type': 'network_connection',
                        'indicator': domain,
                        'file': str(log_path),
                        'severity': 'critical'
                    })
                    self.results['risk_score'] += 15
            
            # Check for Anubis domains
            for domain in self.anubis_iocs['domains']:
                if domain in content:
                    self.results['anubis_indicators'].append({
                        'type': 'network_connection',
                        'indicator': domain,
                        'file': str(log_path),
                        'severity': 'critical'
                    })
                    self.results['risk_score'] += 15
                    
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
                # Check for Predator processes
                if any(proc in rel_path for proc in self.predator_iocs['processes']):
                    self.results['predator_indicators'].append({
                        'type': 'suspicious_process',
                        'indicator': rel_path,
                        'domain': domain,
                        'severity': 'medium'
                    })
                    self.results['risk_score'] += 5
                
                # Check for Pegasus processes and bundle IDs
                if any(proc in rel_path for proc in self.pegasus_iocs['processes']):
                    self.results['pegasus_indicators'].append({
                        'type': 'suspicious_process',
                        'indicator': rel_path,
                        'domain': domain,
                        'severity': 'high'
                    })
                    self.results['risk_score'] += 10
                
                if any(bundle_id in rel_path for bundle_id in self.pegasus_iocs['bundle_ids']):
                    self.results['pegasus_indicators'].append({
                        'type': 'suspicious_bundle_id',
                        'indicator': rel_path,
                        'domain': domain,
                        'severity': 'high'
                    })
                    self.results['risk_score'] += 10
                
                # Check for NJRat processes
                if any(proc in rel_path for proc in self.njrat_iocs['processes']):
                    self.results['njrat_indicators'].append({
                        'type': 'suspicious_process',
                        'indicator': rel_path,
                        'domain': domain,
                        'severity': 'high'
                    })
                    self.results['risk_score'] += 10
                
                # Check for Remcos processes
                if any(proc in rel_path for proc in self.remcos_iocs['processes']):
                    self.results['remcos_indicators'].append({
                        'type': 'suspicious_process',
                        'indicator': rel_path,
                        'domain': domain,
                        'severity': 'high'
                    })
                    self.results['risk_score'] += 10
                
                # Check for AsyncRAT processes
                if any(proc in rel_path for proc in self.asyncrat_iocs['processes']):
                    self.results['asyncrat_indicators'].append({
                        'type': 'suspicious_process',
                        'indicator': rel_path,
                        'domain': domain,
                        'severity': 'high'
                    })
                    self.results['risk_score'] += 10
                
                # Check for DarkGate processes
                if any(proc in rel_path for proc in self.darkgate_iocs['processes']):
                    self.results['darkgate_indicators'].append({
                        'type': 'suspicious_process',
                        'indicator': rel_path,
                        'domain': domain,
                        'severity': 'high'
                    })
                    self.results['risk_score'] += 10
                
                # Check for Anubis processes and bundle IDs
                if any(proc in rel_path for proc in self.anubis_iocs['processes']):
                    self.results['anubis_indicators'].append({
                        'type': 'suspicious_process',
                        'indicator': rel_path,
                        'domain': domain,
                        'severity': 'high'
                    })
                    self.results['risk_score'] += 10
                
                if any(bundle_id in rel_path for bundle_id in self.anubis_iocs['bundle_ids']):
                    self.results['anubis_indicators'].append({
                        'type': 'suspicious_bundle_id',
                        'indicator': rel_path,
                        'domain': domain,
                        'severity': 'high'
                    })
                    self.results['risk_score'] += 10
                    
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
        suspicious_extensions = ['.dylib', '.framework', '.bundle', '.exe', '.dll']
        
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
                    
                    if file_hash in self.pegasus_iocs['file_hashes']:
                        self.results['pegasus_indicators'].append({
                            'type': 'malicious_file',
                            'indicator': file_hash,
                            'file': str(file_path),
                            'severity': 'critical'
                        })
                        self.results['risk_score'] += 20
                    
                    if file_hash in self.njrat_iocs['file_hashes']:
                        self.results['njrat_indicators'].append({
                            'type': 'malicious_file',
                            'indicator': file_hash,
                            'file': str(file_path),
                            'severity': 'critical'
                        })
                        self.results['risk_score'] += 20
                    
                    if file_hash in self.remcos_iocs['file_hashes']:
                        self.results['remcos_indicators'].append({
                            'type': 'malicious_file',
                            'indicator': file_hash,
                            'file': str(file_path),
                            'severity': 'critical'
                        })
                        self.results['risk_score'] += 20
                    
                    if file_hash in self.asyncrat_iocs['file_hashes']:
                        self.results['asyncrat_indicators'].append({
                            'type': 'malicious_file',
                            'indicator': file_hash,
                            'file': str(file_path),
                            'severity': 'critical'
                        })
                        self.results['risk_score'] += 20
                    
                    if file_hash in self.darkgate_iocs['file_hashes']:
                        self.results['darkgate_indicators'].append({
                            'type': 'malicious_file',
                            'indicator': file_hash,
                            'file': str(file_path),
                            'severity': 'critical'
                        })
                        self.results['risk_score'] += 20
                    
                    if file_hash in self.anubis_iocs['file_hashes']:
                        self.results['anubis_indicators'].append({
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
            
        print("\n🔴 PEGASUS SPYWARE IOCs:")
        print("  Domains:")
        for domain in self.pegasus_iocs['domains']:
            print(f"    • {domain}")
        print("  Suspicious Processes:")
        for process in self.pegasus_iocs['processes']:
            print(f"    • {process}")
        print("  Bundle IDs:")
        for bundle_id in self.pegasus_iocs['bundle_ids']:
            print(f"    • {bundle_id}")
        print("  File Hashes (SHA-256):")
        for hash_val in self.pegasus_iocs['file_hashes']:
            print(f"    • {hash_val[:16]}...")
            
        print("\n🔴 NJRAT IOCs:")
        print("  Domains:")
        for domain in self.njrat_iocs['domains']:
            print(f"    • {domain}")
        print("  Suspicious Processes:")
        for process in self.njrat_iocs['processes']:
            print(f"    • {process}")
        print("  File Hashes (SHA-256):")
        for hash_val in self.njrat_iocs['file_hashes']:
            print(f"    • {hash_val[:16]}...")
            
        print("\n🔴 REMCOS IOCs:")
        print("  Domains:")
        for domain in self.remcos_iocs['domains']:
            print(f"    • {domain}")
        print("  Suspicious Processes:")
        for process in self.remcos_iocs['processes']:
            print(f"    • {process}")
        print("  File Hashes (SHA-256):")
        for hash_val in self.remcos_iocs['file_hashes']:
            print(f"    • {hash_val[:16]}...")
            
        print("\n🔴 ASYNCRAT IOCs:")
        print("  Domains:")
        for domain in self.asyncrat_iocs['domains']:
            print(f"    • {domain}")
        print("  Suspicious Processes:")
        for process in self.asyncrat_iocs['processes']:
            print(f"    • {process}")
        print("  File Hashes (SHA-256):")
        for hash_val in self.asyncrat_iocs['file_hashes']:
            print(f"    • {hash_val[:16]}...")
            
        print("\n🔴 DARKGATE RAT IOCs:")
        print("  Domains:")
        for domain in self.darkgate_iocs['domains']:
            print(f"    • {domain}")
        print("  Suspicious Processes:")
        for process in self.darkgate_iocs['processes']:
            print(f"    • {process}")
        print("  File Hashes (SHA-256):")
        for hash_val in self.darkgate_iocs['file_hashes']:
            print(f"    • {hash_val[:16]}...")
            
        print("\n🔴 ANUBIS IOCs:")
        print("  Domains:")
        for domain in self.anubis_iocs['domains']:
            print(f"    • {domain}")
        print("  Suspicious Processes:")
        for process in self.anubis_iocs['processes']:
            print(f"    • {process}")
        print("  Bundle IDs:")
        for bundle_id in self.anubis_iocs['bundle_ids']:
            print(f"    • {bundle_id}")
        print("  File Hashes (SHA-256):")
        for hash_val in self.anubis_iocs['file_hashes']:
            print(f"    • {hash_val[:16]}...")
        
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
            
        # Pegasus indicators
        if self.results['pegasus_indicators']:
            print(f"\n🚨 PEGASUS SPYWARE INDICATORS: {len(self.results['pegasus_indicators'])}")
            for indicator in self.results['pegasus_indicators']:
                print(f"  • {indicator['type']}: {indicator['indicator']} (Severity: {indicator['severity']})")
        else:
            print(f"\n✅ PEGASUS SPYWARE: No indicators found")
            
        # NJRat indicators
        if self.results['njrat_indicators']:
            print(f"\n🚨 NJRAT INDICATORS: {len(self.results['njrat_indicators'])}")
            for indicator in self.results['njrat_indicators']:
                print(f"  • {indicator['type']}: {indicator['indicator']} (Severity: {indicator['severity']})")
        else:
            print(f"\n✅ NJRAT: No indicators found")
            
        # Remcos indicators
        if self.results['remcos_indicators']:
            print(f"\n🚨 REMCOS INDICATORS: {len(self.results['remcos_indicators'])}")
            for indicator in self.results['remcos_indicators']:
                print(f"  • {indicator['type']}: {indicator['indicator']} (Severity: {indicator['severity']})")
        else:
            print(f"\n✅ REMCOS: No indicators found")
            
        # AsyncRAT indicators
        if self.results['asyncrat_indicators']:
            print(f"\n🚨 ASYNCRAT INDICATORS: {len(self.results['asyncrat_indicators'])}")
            for indicator in self.results['asyncrat_indicators']:
                print(f"  • {indicator['type']}: {indicator['indicator']} (Severity: {indicator['severity']})")
        else:
            print(f"\n✅ ASYNCRAT: No indicators found")
            
        # DarkGate indicators
        if self.results['darkgate_indicators']:
            print(f"\n🚨 DARKGATE RAT INDICATORS: {len(self.results['darkgate_indicators'])}")
            for indicator in self.results['darkgate_indicators']:
                print(f"  • {indicator['type']}: {indicator['indicator']} (Severity: {indicator['severity']})")
        else:
            print(f"\n✅ DARKGATE RAT: No indicators found")
            
        # Anubis indicators
        if self.results['anubis_indicators']:
            print(f"\n🚨 ANUBIS INDICATORS: {len(self.results['anubis_indicators'])}")
            for indicator in self.results['anubis_indicators']:
                print(f"  • {indicator['type']}: {indicator['indicator']} (Severity: {indicator['severity']})")
        else:
            print(f"\n✅ ANUBIS: No indicators found")
        
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
    import sys
    import os
    
    parser = argparse.ArgumentParser(description='Advanced Spyware Detection for iOS')
    parser.add_argument('--backup', help='Path to iTunes backup directory')
    parser.add_argument('--diagnostic', help='Path to diagnostic files')
    parser.add_argument('--report', help='Custom path for report output')
    parser.add_argument('--quiet', action='store_true', help='Suppress console output (results still saved to file)')
    parser.add_argument('--json-only', action='store_true', help='Output only JSON data (for programmatic use)')
    parser.add_argument('--version', action='store_true', help='Display version information')
    parser.add_argument('--prerequisites', action='store_true', help='Display prerequisites and requirements')
    parser.add_argument('--ioc-database', action='store_true', help='Display IOC database')
    parser.add_argument('--risk-map', action='store_true', help='Display risk assessment matrix')
    
    args = parser.parse_args()
    
    # Version information
    if args.version:
        print("Paranoid - Advanced iOS Spyware Detection Tool")
        print("Version: 1.1.0")
        print("Last Updated: June 2024")
        print("Supports: iOS 12.0 - 17.x")
        return
    
    # Create detector instance
    detector = AdvancedSpywareDetector(
        backup_path=args.backup,
        diagnostic_path=args.diagnostic
    )
    
    # Display prerequisites only
    if args.prerequisites:
        detector.print_prerequisites()
        return
        
    # Display IOC database only
    if args.ioc_database:
        detector.print_ioc_database()
        return
        
    # Display risk map only
    if args.risk_map:
        detector.print_risk_map()
        return
    
    # Full scan mode requires at least one data source
    if not args.backup and not args.diagnostic:
        print("Error: Please provide either --backup or --diagnostic path")
        parser.print_help()
        return
    
    # Setup custom report path if specified
    report_path = args.report if args.report else 'spyware_detection_report.json'
    
    # Configure quiet mode
    if args.quiet:
        # Redirect stdout to null
        sys.stdout = open(os.devnull, 'w')
    
    # Run the scan
    results = detector.run_full_scan()
    
    # Restore stdout if needed
    if args.quiet:
        sys.stdout = sys.__stdout__
    
    # Save results to specified path
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