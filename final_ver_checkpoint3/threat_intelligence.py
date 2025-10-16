#!/usr/bin/env python3
"""
Dynamic Threat Intelligence Scoring Engine with Real APIs
Real-time threat assessment using multiple threat intelligence feeds
"""

import requests
import json
import hashlib
import time
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass
from collections import defaultdict
import ipaddress
import base64
import re

@dataclass
class ThreatScore:
    """Container for threat assessment results"""
    total_score: int
    breakdown: Dict[str, int]
    action: str
    details: Dict[str, str]
    api_responses: Dict[str, dict]

class ThreatIntelEngine:
    """Dynamic threat intelligence scoring engine with real APIs"""
    
    def __init__(self, abuseipdb_key: str = None, virustotal_key: str = None):
        # API Keys (get free keys from respective services)
        self.abuseipdb_key = abuseipdb_key
        self.virustotal_key = virustotal_key
        
        # API endpoints
        self.abuseipdb_url = "https://api.abuseipdb.com/api/v2/check"
        self.virustotal_url = "https://www.virustotal.com/vtapi/v2"
        self.otx_url = "https://otx.alienvault.com/api/v1"
        
        # Request tracking for behavioral analysis
        self.request_history = defaultdict(list)
        
        # Scoring thresholds
        self.thresholds = {
            "safe": 3,
            "suspicious": 7,
            "malicious": 8
        }
        
        # Rate limiting
        self.api_cache = {}
        self.cache_ttl = 300  # 5 minutes
        
        # Known malicious user agents (for offline checking)
        self.malicious_user_agents = {
            "curl/7.68.0", "python-requests/2.28.1", "Scrapy/2.6.1",
            "Go-http-client/1.1", "libwww-perl/6.05", "Wget/1.20.3",
            "sqlmap/1.6.12", "Nikto/2.1.6", "OpenAI-GPTBot", "CCBot/2.0",
            "python-urllib3/1.26.12", "Apache-HttpClient/4.5.13"
        }

    def _get_cached_or_fetch(self, cache_key: str, fetch_func, *args, **kwargs):
        """Generic cache wrapper for API calls"""
        now = time.time()
        
        if cache_key in self.api_cache:
            cached_data, timestamp = self.api_cache[cache_key]
            if now - timestamp < self.cache_ttl:
                return cached_data
        
        try:
            result = fetch_func(*args, **kwargs)
            self.api_cache[cache_key] = (result, now)
            return result
        except Exception as e:
            print(f"API Error for {cache_key}: {e}")
            return None

    def check_abuseipdb(self, ip: str) -> Tuple[int, str, dict]:
        """Check IP reputation using AbuseIPDB API"""
        if not self.abuseipdb_key:
            return 0, "AbuseIPDB API key not provided", {}
        
        cache_key = f"abuseipdb_{ip}"
        
        def _fetch_abuseipdb():
            headers = {
                'Key': self.abuseipdb_key,
                'Accept': 'application/json'
            }
            params = {
                'ipAddress': ip,
                'maxAgeInDays': 90,
                'verbose': ''
            }
            
            response = requests.get(self.abuseipdb_url, headers=headers, params=params, timeout=10)
            response.raise_for_status()
            return response.json()
        
        result = self._get_cached_or_fetch(cache_key, _fetch_abuseipdb)
        
        if not result:
            return 0, "AbuseIPDB API unavailable", {}
        
        try:
            data = result.get('data', {})
            abuse_confidence = data.get('abuseConfidencePercentage', 0)
            is_whitelisted = data.get('isWhitelisted', False)
            usage_type = data.get('usageType', 'unknown')
            
            score = 0
            details = []
            
            if is_whitelisted:
                details.append("IP is whitelisted")
            elif abuse_confidence >= 75:
                score += 7
                details.append(f"High abuse confidence: {abuse_confidence}%")
            elif abuse_confidence >= 50:
                score += 5
                details.append(f"Medium abuse confidence: {abuse_confidence}%")
            elif abuse_confidence >= 25:
                score += 3
                details.append(f"Low abuse confidence: {abuse_confidence}%")
            
            if usage_type in ['hosting', 'datacenter']:
                score += 1
                details.append(f"Usage type: {usage_type}")
            
            return score, "; ".join(details), result
            
        except Exception as e:
            return 0, f"AbuseIPDB parsing error: {e}", result

    def check_virustotal_ip(self, ip: str) -> Tuple[int, str, dict]:
        """Check IP reputation using VirusTotal API"""
        if not self.virustotal_key:
            return 0, "VirusTotal API key not provided", {}
        
        cache_key = f"vt_ip_{ip}"
        
        def _fetch_vt_ip():
            params = {
                'apikey': self.virustotal_key,
                'ip': ip
            }
            response = requests.get(f"{self.virustotal_url}/ip-address/report", params=params, timeout=10)
            response.raise_for_status()
            return response.json()
        
        result = self._get_cached_or_fetch(cache_key, _fetch_vt_ip)
        
        if not result:
            return 0, "VirusTotal IP API unavailable", {}
        
        try:
            response_code = result.get('response_code', 0)
            if response_code != 1:
                return 0, "IP not found in VirusTotal", result
            
            detected_urls = result.get('detected_urls', [])
            malicious_count = len([url for url in detected_urls if url.get('positives', 0) > 0])
            
            score = 0
            details = []
            
            if malicious_count >= 10:
                score += 6
                details.append(f"High malicious URL count: {malicious_count}")
            elif malicious_count >= 5:
                score += 4
                details.append(f"Medium malicious URL count: {malicious_count}")
            elif malicious_count >= 1:
                score += 2
                details.append(f"Low malicious URL count: {malicious_count}")
            
            return score, "; ".join(details), result
            
        except Exception as e:
            return 0, f"VirusTotal IP parsing error: {e}", result

    def check_virustotal_url(self, url: str) -> Tuple[int, str, dict]:
        """Check URL reputation using VirusTotal API"""
        if not self.virustotal_key:
            return 0, "VirusTotal API key not provided", {}
        
        cache_key = f"vt_url_{hashlib.md5(url.encode()).hexdigest()}"
        
        def _fetch_vt_url():
            params = {
                'apikey': self.virustotal_key,
                'resource': url
            }
            response = requests.post(f"{self.virustotal_url}/url/report", data=params, timeout=10)
            response.raise_for_status()
            return response.json()
        
        result = self._get_cached_or_fetch(cache_key, _fetch_vt_url)
        
        if not result:
            return 0, "VirusTotal URL API unavailable", {}
        
        try:
            response_code = result.get('response_code', 0)
            if response_code != 1:
                return 0, "URL not found in VirusTotal", result
            
            positives = result.get('positives', 0)
            total = result.get('total', 1)
            
            score = 0
            details = []
            
            if positives >= 5:
                score += 6
                details.append(f"High detection rate: {positives}/{total} engines")
            elif positives >= 3:
                score += 4
                details.append(f"Medium detection rate: {positives}/{total} engines")
            elif positives >= 1:
                score += 2
                details.append(f"Low detection rate: {positives}/{total} engines")
            
            return score, "; ".join(details), result
            
        except Exception as e:
            return 0, f"VirusTotal URL parsing error: {e}", result

    def check_otx_domain(self, domain: str) -> Tuple[int, str, dict]:
        """Check domain reputation using AlienVault OTX (free, no API key needed)"""
        cache_key = f"otx_domain_{domain}"
        
        def _fetch_otx_domain():
            url = f"{self.otx_url}/indicators/domain/{domain}/general"
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            return response.json()
        
        result = self._get_cached_or_fetch(cache_key, _fetch_otx_domain)
        
        if not result:
            return 0, "OTX API unavailable", {}
        
        try:
            pulse_info = result.get('pulse_info', {})
            pulses = pulse_info.get('pulses', [])
            
            score = 0
            details = []
            
            malicious_pulses = [p for p in pulses if 'malware' in p.get('name', '').lower() or 
                              'phishing' in p.get('name', '').lower() or 
                              'malicious' in p.get('name', '').lower()]
            
            if len(malicious_pulses) >= 3:
                score += 5
                details.append(f"High threat pulse count: {len(malicious_pulses)}")
            elif len(malicious_pulses) >= 1:
                score += 3
                details.append(f"Medium threat pulse count: {len(malicious_pulses)}")
            
            return score, "; ".join(details), result
            
        except Exception as e:
            return 0, f"OTX parsing error: {e}", result

    def check_shodan_ip(self, ip: str, shodan_key: str = None) -> Tuple[int, str, dict]:
        """Check IP information using Shodan API (optional)"""
        if not shodan_key:
            return 0, "Shodan API key not provided", {}
        
        cache_key = f"shodan_{ip}"
        
        def _fetch_shodan():
            url = f"https://api.shodan.io/shodan/host/{ip}"
            params = {'key': shodan_key}
            response = requests.get(url, params=params, timeout=10)
            response.raise_for_status()
            return response.json()
        
        result = self._get_cached_or_fetch(cache_key, _fetch_shodan)
        
        if not result:
            return 0, "Shodan API unavailable", {}
        
        try:
            ports = result.get('ports', [])
            tags = result.get('tags', [])
            
            score = 0
            details = []
            
            # Suspicious open ports
            suspicious_ports = [22, 23, 135, 445, 1433, 3389, 5900, 6379]
            open_suspicious = [p for p in ports if p in suspicious_ports]
            
            if len(open_suspicious) >= 3:
                score += 3
                details.append(f"Multiple suspicious ports: {open_suspicious}")
            elif len(open_suspicious) >= 1:
                score += 1
                details.append(f"Suspicious ports: {open_suspicious}")
            
            # Malicious tags
            malicious_tags = [tag for tag in tags if tag in ['malware', 'botnet', 'honeypot']]
            if malicious_tags:
                score += 4
                details.append(f"Malicious tags: {malicious_tags}")
            
            return score, "; ".join(details), result
            
        except Exception as e:
            return 0, f"Shodan parsing error: {e}", result

    def check_user_agent(self, user_agent: str) -> Tuple[int, str, dict]:
        """Check User-Agent against known patterns"""
        score = 0
        details = []
        
        if not user_agent:
            return 2, "Missing User-Agent header", {}
        
        # Check against known malicious user agents
        if user_agent in self.malicious_user_agents:
            score += 4
            details.append("Known malicious/bot User-Agent")
        
        # Bot patterns
        bot_patterns = [
            r'bot|crawl|spider|scraper|scanner',
            r'python|curl|wget|go-http',
            r'sqlmap|nikto|nessus|openvas'
        ]
        
        for pattern in bot_patterns:
            if re.search(pattern, user_agent.lower()):
                score += 2
                details.append("Bot/automation tool detected")
                break
        
        # Suspicious characteristics
        if len(user_agent) < 10:
            score += 2
            details.append("Suspiciously short User-Agent")
        
        return score, "; ".join(details), {"user_agent": user_agent}

    def check_behavioral_patterns(self, ip: str, timestamp: Optional[datetime] = None) -> Tuple[int, str, dict]:
        """Analyze request patterns for suspicious behavior"""
        score = 0
        details = []
        
        if timestamp is None:
            timestamp = datetime.now()
        
        # Add current request to history
        self.request_history[ip].append(timestamp)
        
        # Clean old entries (keep last 24 hours)
        cutoff = timestamp - timedelta(hours=24)
        self.request_history[ip] = [
            ts for ts in self.request_history[ip] if ts > cutoff
        ]
        
        recent_requests = len(self.request_history[ip])
        
        # High frequency analysis
        if recent_requests > 100:
            score += 3
            details.append(f"High frequency: {recent_requests} requests/24h")
        elif recent_requests > 50:
            score += 2
            details.append(f"Elevated frequency: {recent_requests} requests/24h")
        
        # Burst detection
        if len(self.request_history[ip]) >= 10:
            recent_10 = sorted(self.request_history[ip])[-10:]
            time_span = (recent_10[-1] - recent_10[0]).total_seconds()
            if time_span < 60:
                score += 2
                details.append("Burst pattern detected (10 req/min)")
        
        return score, "; ".join(details), {"request_count": recent_requests}

    def assess_threat(self, ip: str, domain: str = "", url: str = "", user_agent: str = "",
                     timestamp: Optional[datetime] = None, shodan_key: str = None) -> ThreatScore:
        """
        Main threat assessment function with real APIs
        """
        breakdown = {}
        details = {}
        api_responses = {}
        
        print(f"🔍 Analyzing threat for IP: {ip}")
        
        # 1. AbuseIPDB Check
        print("  📡 Checking AbuseIPDB...")
        ip_score, ip_details, ip_response = self.check_abuseipdb(ip)
        breakdown['abuseipdb'] = ip_score
        details['abuseipdb'] = ip_details
        api_responses['abuseipdb'] = ip_response
        
        # 2. VirusTotal IP Check
        print("  📡 Checking VirusTotal IP...")
        vt_ip_score, vt_ip_details, vt_ip_response = self.check_virustotal_ip(ip)
        breakdown['virustotal_ip'] = vt_ip_score
        details['virustotal_ip'] = vt_ip_details
        api_responses['virustotal_ip'] = vt_ip_response
        
        # 3. Domain reputation (if provided)
        if domain:
            print(f"  📡 Checking domain: {domain}")
            otx_score, otx_details, otx_response = self.check_otx_domain(domain)
            breakdown['otx_domain'] = otx_score
            details['otx_domain'] = otx_details
            api_responses['otx_domain'] = otx_response
        
        # 4. URL reputation (if provided)
        if url:
            print(f"  📡 Checking URL...")
            vt_url_score, vt_url_details, vt_url_response = self.check_virustotal_url(url)
            breakdown['virustotal_url'] = vt_url_score
            details['virustotal_url'] = vt_url_details
            api_responses['virustotal_url'] = vt_url_response
        
        # 5. User-Agent analysis
        ua_score, ua_details, ua_response = self.check_user_agent(user_agent)
        breakdown['user_agent'] = ua_score
        details['user_agent'] = ua_details
        api_responses['user_agent'] = ua_response
        
        # 6. Behavioral analysis
        behavior_score, behavior_details, behavior_response = self.check_behavioral_patterns(ip, timestamp)
        breakdown['behavioral'] = behavior_score
        details['behavioral'] = behavior_details
        api_responses['behavioral'] = behavior_response
        
        # 7. Optional Shodan check
        if shodan_key:
            print("  📡 Checking Shodan...")
            shodan_score, shodan_details, shodan_response = self.check_shodan_ip(ip, shodan_key)
            breakdown['shodan'] = shodan_score
            details['shodan'] = shodan_details
            api_responses['shodan'] = shodan_response
        
        # Calculate total score
        total_score = sum(breakdown.values())
        
        # Determine action
        if total_score <= self.thresholds['safe']:
            action = "ALLOW"
        elif total_score <= self.thresholds['suspicious']:
            action = "CHALLENGE"
        else:
            action = "BLOCK"
        
        print(f"  ✅ Analysis complete. Total score: {total_score}, Action: {action}")
        
        return ThreatScore(
            total_score=total_score,
            breakdown=breakdown,
            action=action,
            details=details,
            api_responses=api_responses
        )
# Compatibility method names
ThreatIntelEngine.check_abuseipdb = ThreatIntelEngine.checkabuseipdb
ThreatIntelEngine.check_virustotal_ip = ThreatIntelEngine.checkvirustotalip
ThreatIntelEngine.check_virustotal_url = ThreatIntelEngine.checkvirustotalurl
ThreatIntelEngine.check_useragent = ThreatIntelEngine.checkuseragent


def demo_with_real_apis():
    """Demo with real API integration"""
    print("🚦 Dynamic Threat Intelligence Engine - Real API Demo")
    print("=" * 60)
    
    # Initialize with API keys (replace with your actual keys)
    abuseipdb_key = input("Enter AbuseIPDB API key (or press Enter to skip): ").strip()
    virustotal_key = input("Enter VirusTotal API key (or press Enter to skip): ").strip()
    shodan_key = input("Enter Shodan API key (optional, press Enter to skip): ").strip()
    
    if not abuseipdb_key and not virustotal_key:
        print("\n⚠️  No API keys provided. Get free keys from:")
        print("   • AbuseIPDB: https://www.abuseipdb.com/api")
        print("   • VirusTotal: https://developers.virustotal.com/reference")
        return
    
    engine = ThreatIntelEngine(abuseipdb_key, virustotal_key)
    
    # Test with real IPs (use known bad IPs for testing)
    test_cases = [
        {
            "name": "Test IP #1",
            "ip": "185.220.101.32",  # Known Tor exit node
            "domain": "facebook.com",
            "url": "https://facebook.com/login",
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        },
        {
            "name": "Test IP #2", 
            "ip": "198.51.100.1",  # Test IP
            "domain": "google.com",
            "url": "https://google.com/search?q=test",
            "user_agent": "python-requests/2.28.1"
        }
    ]
    
    for i, test_case in enumerate(test_cases, 1):
        print(f"\n🧪 Test Case {i}: {test_case['name']}")
        print("-" * 50)
        
        result = engine.assess_threat(
            test_case['ip'],
            test_case['domain'], 
            test_case['url'],
            test_case['user_agent'],
            shodan_key=shodan_key if shodan_key else None
        )
        
        print(f"\n📊 Results:")
        print(f"   Total Risk Score: {result.total_score}")
        print(f"   Action: {result.action}")
        print(f"\n📋 Score Breakdown:")
        for category, score in result.breakdown.items():
            if score > 0:
                print(f"   • {category.replace('_', ' ').title()}: +{score}")
                if result.details[category]:
                    print(f"     → {result.details[category]}")
        
        action_emoji = {
            "ALLOW": "🟢",
            "CHALLENGE": "🟡", 
            "BLOCK": "🔴"
        }
        print(f"\n{action_emoji[result.action]} Final Decision: {result.action}")

if __name__ == "__main__":
    demo_with_real_apis()
