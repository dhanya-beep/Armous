#!/usr/bin/env python3
# ============================================================================
# HTTP Request Analyzer - Input Your Own Request Files
# Analyzes HTTP headers from YOUR uploaded text files
# ============================================================================

import re
import math
import json
import os
import sys
from collections import Counter
from datetime import datetime
from typing import Dict, List, Tuple, Optional

class HTTPRequestAnalyzer:
    def __init__(self):
        # Traditional bot signatures
        self.BOT_SIGNATURES = [
            "HeadlessChrome", "PhantomJS", "Scrapy", "Puppeteer",
            "python-requests", "curl", "wget", "httpx", "aiohttp",
            "Selenium", "playwright", "BeautifulSoup", "urllib",
            "mechanize", "requests-html", "httplib2", "boto3"
        ]
        
        # LLM/AI bot signatures
        self.LLM_SIGNATURES = [
            "OpenAI", "GPT", "Claude", "ChatGPT", "Anthropic",
            "AI-Agent", "LangChain", "AutoGPT", "AgentGPT",
            "Bard", "PaLM", "LLaMA", "Gemini", "AI-Scraper",
            "LLM-Bot", "AI-Assistant", "WebPilot", "semantic-kernel"
        ]

    def parse_request_file(self, file_path: str) -> Dict:
        """Parse HTTP request from YOUR text file"""
        print(f"📖 Reading file: {file_path}")
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read().strip()
        except FileNotFoundError:
            print(f"❌ Error: File '{file_path}' not found!")
            print("Make sure the file exists in the current directory.")
            return {}
        except Exception as e:
            print(f"❌ Error reading file: {e}")
            return {}
        
        print(f"✅ File loaded successfully ({len(content)} characters)")
        
        # Initialize request data
        request_data = {
            'method': 'UNKNOWN',
            'path': '/',
            'ip': 'UNKNOWN',
            'headers': {},
            'raw_content': content
        }
        
        lines = content.split('\n')
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            # Parse request line (GET /path HTTP/1.1)
            if re.match(r'^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)', line, re.I):
                parts = line.split()
                if len(parts) >= 2:
                    request_data['method'] = parts[0].upper()
                    request_data['path'] = parts[1]
                continue
            
            # Parse headers (Key: Value format)
            if ':' in line:
                key, value = line.split(':', 1)
                request_data['headers'][key.strip()] = value.strip()
                continue
            
            # Look for IP patterns
            ip_match = re.search(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', line)
            if ip_match and request_data['ip'] == 'UNKNOWN':
                request_data['ip'] = ip_match.group(1)
        
        # Extract IP from headers if not found
        if request_data['ip'] == 'UNKNOWN':
            for header_key, header_value in request_data['headers'].items():
                if any(keyword in header_key.lower() for keyword in ['ip', 'forwarded', 'real', 'client']):
                    ip_match = re.search(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', header_value)
                    if ip_match:
                        request_data['ip'] = ip_match.group(1)
                        break
        
        print(f"📋 Parsed: {request_data['method']} {request_data['path']}")
        print(f"🌐 IP: {request_data['ip']}")
        print(f"📊 Headers found: {len(request_data['headers'])}")
        
        return request_data

    def calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy"""
        if not text:
            return 0.0
        counter = Counter(text)
        length = len(text)
        entropy = -sum((count/length) * math.log2(count/length) for count in counter.values())
        return entropy

    def analyze_user_agent(self, ua: str) -> Dict:
        """Analyze User-Agent for bot/human indicators"""
        findings = []
        score = 0
        
        if not ua:
            return {"findings": ["Missing User-Agent header"], "score": 10}
        
        print(f"🔍 Analyzing User-Agent: {ua[:80]}{'...' if len(ua) > 80 else ''}")
        
        # Length analysis
        if len(ua) < 20:
            findings.append(f"Very short User-Agent ({len(ua)} chars)")
            score += 15
        elif len(ua) < 50:
            findings.append(f"Short User-Agent ({len(ua)} chars)")
            score += 5
        
        # Entropy analysis
        entropy = self.calculate_entropy(ua)
        if entropy < 3.0:
            findings.append(f"Low entropy User-Agent ({entropy:.2f})")
            score += 10
        
        # Bot signature detection
        for signature in self.BOT_SIGNATURES:
            if signature.lower() in ua.lower():
                findings.append(f"🤖 BOT DETECTED: {signature}")
                score += 25
                break
        
        # LLM signature detection  
        for signature in self.LLM_SIGNATURES:
            if signature.lower() in ua.lower():
                findings.append(f"🧠 LLM/AI DETECTED: {signature}")
                score += 30
                break
        
        # Browser legitimacy checks
        if "mozilla" in ua.lower():
            if not re.search(r'chrome|firefox|safari|edge', ua.lower()):
                findings.append("Generic Mozilla User-Agent (suspicious)")
                score += 10
            
            if len(ua) < 60:
                findings.append("Mozilla User-Agent too short")
                score += 8
        
        # Headless browser detection
        if any(term in ua.lower() for term in ['headless', 'phantom', 'zombie']):
            findings.append("🤖 Headless browser detected")
            score += 20
        
        return {"findings": findings, "score": score, "entropy": entropy, "length": len(ua)}

    def analyze_headers(self, headers: Dict[str, str]) -> Dict:
        """Analyze all headers for suspicious patterns"""
        findings = []
        score = 0
        
        print(f"🔍 Analyzing {len(headers)} headers...")
        
        # Required header checks
        if "Accept" not in headers:
            findings.append("Missing Accept header")
            score += 10
        elif headers["Accept"] == "*/*":
            findings.append("Generic Accept header (*/*)")
            score += 5
        
        if "Accept-Language" not in headers:
            findings.append("Missing Accept-Language header")
            score += 8
        
        if "Accept-Encoding" not in headers:
            findings.append("Missing Accept-Encoding header")
            score += 5
        
        # Header count analysis
        if len(headers) < 3:
            findings.append(f"Too few headers ({len(headers)})")
            score += 15
        elif len(headers) > 25:
            findings.append(f"Too many headers ({len(headers)})")
            score += 5
        
        # Connection header
        connection = headers.get("Connection", "").lower()
        if connection == "close" and any("mozilla" in h.lower() for h in headers.values()):
            findings.append("Browser with Connection: close (unusual)")
            score += 5
        
        return {"findings": findings, "score": score}

    def analyze_request_file(self, file_path: str) -> Dict:
        """Main function to analyze YOUR request file"""
        print("\n" + "="*70)
        print("🔍 HTTP REQUEST ANALYSIS STARTING")
        print("="*70)
        
        # Parse the file
        request_data = self.parse_request_file(file_path)
        
        if not request_data or not request_data.get('headers'):
            return {
                'error': f'Could not parse HTTP request from file: {file_path}',
                'suggestions': [
                    'Make sure file contains HTTP headers in format: "Header-Name: value"',
                    'Include at least User-Agent and Accept headers',
                    'Check file encoding (should be UTF-8)'
                ]
            }
        
        print("\n🔍 DETAILED ANALYSIS:")
        print("-" * 40)
        
        # Analyze User-Agent
        ua_analysis = self.analyze_user_agent(request_data['headers'].get('User-Agent', ''))
        
        # Analyze Headers
        header_analysis = self.analyze_headers(request_data['headers'])
        
        # Calculate final score
        total_score = ua_analysis['score'] + header_analysis['score']
        all_findings = ua_analysis['findings'] + header_analysis['findings']
        
        # Determine classification
        if any('LLM/AI DETECTED' in f for f in all_findings):
            classification = "🧠 LLM/AI SCRAPER"
            threat_level = "HIGH"
        elif any('BOT DETECTED' in f for f in all_findings) or total_score > 20:
            classification = "🤖 TRADITIONAL BOT"  
            threat_level = "MEDIUM"
        elif total_score > 10:
            classification = "⚠️ SUSPICIOUS"
            threat_level = "LOW"
        else:
            classification = "✅ LIKELY HUMAN"
            threat_level = "NONE"
        
        # Prepare final result
        result = {
            'file_name': os.path.basename(file_path),
            'classification': classification,
            'threat_level': threat_level,
            'risk_score': total_score,
            'confidence': min(total_score * 5, 100),  # Convert to percentage
            'request_details': {
                'method': request_data['method'],
                'path': request_data['path'], 
                'ip': request_data['ip'],
                'header_count': len(request_data['headers'])
            },
            'user_agent_analysis': {
                'user_agent': request_data['headers'].get('User-Agent', 'MISSING'),
                'length': ua_analysis.get('length', 0),
                'entropy': round(ua_analysis.get('entropy', 0), 2)
            },
            'findings': all_findings if all_findings else ['No suspicious indicators found'],
            'analysis_timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        
        return result

    def print_result(self, result: Dict):
        """Print analysis result in a nice format"""
        if 'error' in result:
            print(f"\n❌ ERROR: {result['error']}")
            if 'suggestions' in result:
                print("\n💡 SUGGESTIONS:")
                for suggestion in result['suggestions']:
                    print(f"   • {suggestion}")
            return
        
        print("\n" + "="*70)
        print("📊 ANALYSIS RESULTS")
        print("="*70)
        
        print(f"📄 File: {result['file_name']}")
        print(f"🎯 Classification: {result['classification']}")
        print(f"⚠️ Threat Level: {result['threat_level']}")
        print(f"📊 Risk Score: {result['risk_score']}/50")
        print(f"🔍 Confidence: {result['confidence']}%")
        
        print(f"\n📋 REQUEST DETAILS:")
        details = result['request_details']
        print(f"   Method: {details['method']}")
        print(f"   Path: {details['path']}")
        print(f"   IP: {details['ip']}")
        print(f"   Headers: {details['header_count']}")
        
        print(f"\n🔍 USER-AGENT ANALYSIS:")
        ua_analysis = result['user_agent_analysis']
        print(f"   User-Agent: {ua_analysis['user_agent'][:100]}{'...' if len(ua_analysis['user_agent']) > 100 else ''}")
        print(f"   Length: {ua_analysis['length']} characters")
        print(f"   Entropy: {ua_analysis['entropy']}")
        
        print(f"\n🚩 FINDINGS:")
        findings = result['findings']
        if findings and findings[0] != 'No suspicious indicators found':
            for i, finding in enumerate(findings, 1):
                print(f"   {i}. {finding}")
        else:
            print("   ✅ No suspicious indicators found")
        
        print(f"\n⏰ Analysis completed: {result['analysis_timestamp']}")
        print("="*70)

def main():
    if len(sys.argv) != 2:
        print("="*50)
        print("HTTP REQUEST ANALYZER")
        print("="*50)
        print("\n📝 USAGE:")
        print(f"   python3 {os.path.basename(sys.argv[0])} <your_request_file.txt>")
        print(f"   python3 {os.path.basename(sys.argv[0])} my_request.txt")
        
        print("\n📄 EXAMPLE INPUT FILE FORMAT:")
        print("Create a file called 'request.txt' with content like:")
        print("-" * 30)
        print("GET /api/products HTTP/1.1")
        print("Host: example.com")
        print("User-Agent: python-requests/2.28.1")
        print("Accept: */*")
        print("Accept-Encoding: gzip, deflate")
        print("Connection: keep-alive")
        print("X-Forwarded-For: 192.168.1.100")
        print("-" * 30)
        
        print("\n🚀 THEN RUN:")
        print(f"   python3 {os.path.basename(sys.argv[0])} request.txt")
        return
    
    # Get the file path from command line
    file_path = sys.argv[1]
    
    # Create analyzer and process the file
    analyzer = HTTPRequestAnalyzer()
    result = analyzer.analyze_request_file(file_path)
    
    # Print results
    analyzer.print_result(result)
    
    # Ask if user wants JSON output
    try:
        save_json = input("\n💾 Save detailed results as JSON? (y/N): ").lower().strip()
        if save_json in ['y', 'yes']:
            output_file = f"analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(output_file, 'w') as f:
                json.dump(result, f, indent=2)
            print(f"✅ Results saved to: {output_file}")
    except KeyboardInterrupt:
        print("\n👋 Analysis complete!")
# Allow programmatic use
def analyze_request_file(filepath: str):
    analyzer = HTTPRequestAnalyzer()
    return analyzer.analyze_request_file(filepath)

if __name__ == "__main__":
    main()
