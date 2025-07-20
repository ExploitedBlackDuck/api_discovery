#!/usr/bin/env python3
"""
Hybrid API Endpoint Discovery Script with Advanced AI Integration
Production-ready tool for security assessments
"""

import requests
import argparse
import threading
import time
import sys
import os
import signal
import logging
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Default SecLists wordlist URL (verified active as of 2025)
WORDLIST_URL = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/api/api-endpoints.txt"

# Import for Gemini integration
try:
    import google.generativeai as genai
except ImportError:
    print("[!] Google Generative AI SDK not found. Install with: pip install google-generativeai")
    sys.exit(1)

class APIDiscovery:
    def __init__(self, base_url, threads=10, timeout=5, delay=0, quiet=False, custom_headers=None, proxy=None, gemini_api_key=None, gemini_model_name='gemini-2.5-flash', gemini_concurrency=5):
        self.base_url = base_url.rstrip('/')
        self.threads = threads
        self.timeout = timeout
        self.delay = delay
        self.quiet = quiet
        self.found_endpoints = []
        self.completed = 0
        self.total = 0
        self.lock = threading.Lock()
        self.running = True

        # Enhanced interesting response codes for comprehensive discovery
        self.interesting_codes = {200, 201, 202, 204, 301, 302, 307, 308, 400, 401, 403, 405, 422, 429, 500, 502, 503}
        
        # Session with enhanced retry strategy
        self.session = self._create_session(proxy)
        
        # Add custom headers if provided
        if custom_headers:
            self.session.headers.update(custom_headers)
        
        # Gemini setup
        self.gemini_api_key = gemini_api_key
        self.gemini_model = None
        self.gemini_semaphore = threading.Semaphore(gemini_concurrency)  # Rate limit concurrent calls
        self.gemini_backoff = 0.1  # Initial backoff for errors
        if self.gemini_api_key:
            try:
                genai.configure(api_key=self.gemini_api_key)
                self.gemini_model = genai.GenerativeModel(gemini_model_name)  # Default to fast, non-deprecated model
            except Exception as e:
                logging.warning(f"Failed to initialize Gemini: {e}. Disabling AI features.")
                self.gemini_model = None
        else:
            if not self.quiet:
                logging.info("No Gemini API key provided. Disabling AI features.")

    def _create_session(self, proxy):
        """Create requests session with comprehensive retry strategy"""
        session = requests.Session()
        
        # Enhanced retry strategy - includes POST and other methods
        retry_strategy = Retry(
            total=2,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=frozenset(['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'])
        )
        
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        # Realistic browser headers for stealth
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'application/json, text/plain, */*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        })

        # Set proxy if provided
        if proxy:
            session.proxies = {'http': proxy, 'https': proxy}
        
        return session

    def _ask_gemini(self, prompt):
        """Helper to query Gemini with rate-limiting, backoff, and error handling"""
        if not self.gemini_model:
            return None
        with self.gemini_semaphore:
            try:
                response = self.gemini_model.generate_content(prompt)
                self.gemini_backoff = 0.1  # Reset backoff on success
                return response.text
            except Exception as e:
                logging.warning(f"Gemini API error: {e}. Backing off for {self.gemini_backoff}s.")
                time.sleep(self.gemini_backoff)
                self.gemini_backoff = min(self.gemini_backoff * 2, 5)  # Exponential backoff up to 5s
                return None

    def download_wordlist(self, filename="api-endpoints.txt"):
        """Download SecLists API wordlist using plain requests for simplicity"""
        if not self.quiet:
            print(f"[*] Downloading wordlist from SecLists...")
        
        try:
            resp = requests.get(WORDLIST_URL, timeout=10)
            if resp.status_code == 200:
                with open(filename, "w", encoding='utf-8') as f:
                    f.write(resp.text)
                if not self.quiet:
                    print(f"[*] Wordlist saved as {filename}")
                return filename
            else:
                raise Exception(f"HTTP {resp.status_code}")
        except Exception as e:
            print(f"[!] Failed to download wordlist: {e}")
            print(f"[!] Consider using a custom wordlist with -w option")
            sys.exit(1)

    def load_wordlist(self, wordlist_file):
        """Load wordlist from file or download if needed"""
        if wordlist_file is None:
            if not os.path.exists("api-endpoints.txt"):
                wordlist_file = self.download_wordlist()
            else:
                wordlist_file = "api-endpoints.txt"
                if not self.quiet:
                    print(f"[*] Using existing wordlist: {wordlist_file}")
        
        try:
            with open(wordlist_file, 'r', encoding='utf-8', errors='ignore') as f:
                paths = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            if not paths:
                print("[!] Empty wordlist after loading")
                sys.exit(1)
            return paths
        except FileNotFoundError:
            print(f"[!] Wordlist file '{wordlist_file}' not found")
            sys.exit(1)
        except Exception as e:
            print(f"[!] Error reading wordlist: {e}")
            sys.exit(1)

    def generate_ai_paths(self, num_paths=100):
        """Use Gemini API to generate additional potential API paths"""
        if not self.gemini_model:
            if not self.quiet:
                print("[!] Gemini not configured; skipping AI path generation")
            return []

        try:
            domain = urlparse(self.base_url).netloc
            prompt = (
                f"Generate a list of {num_paths} potential REST API endpoints for a web application at {domain}. "
                "Focus on common patterns for resources like users, auth, products, orders, search, admin, etc. "
                "Include variations with HTTP methods implied (e.g., /api/users, /v1/auth/login). "
                "Output as a bullet list: - /path1\n- /path2, no explanations or numbering."
            )
            response_text = self._ask_gemini(prompt)
            if response_text:
                ai_paths = [path.strip('- ').strip() for path in response_text.split('\n') if path.strip()]
                if not self.quiet:
                    print(f"[*] Generated {len(ai_paths)} AI-suggested paths using Gemini")
                return ai_paths
            return []
        except Exception as e:
            print(f"[!] Error generating AI paths with Gemini: {e}")
            return []

    def generate_dynamic_paths(self, found_patterns, num_paths=50):
        """Use Gemini to suggest additional paths based on discovered patterns"""
        if not self.gemini_model:
            return []

        try:
            # Summarize if too many patterns to fit context
            if len(found_patterns) > 10:
                summary_prompt = (
                    f"Summarize these endpoint patterns into 5-10 key themes or examples: {', '.join(found_patterns)}. "
                    "Output as a concise list."
                )
                patterns_summary = self._ask_gemini(summary_prompt) or ', '.join(found_patterns[:10])
            else:
                patterns_summary = ', '.join(found_patterns)
            
            prompt = (
                f"I'm performing API endpoint discovery and have found these patterns: {patterns_summary}. "
                f"Suggest {num_paths} additional path variations or related sub-paths (e.g., for /api/users, suggest /api/users/{{id}}/details). "
                "Include potential parameterized or vulnerability-testing paths like /api/users/../admin. "
                "Output as a bullet list: - /path1\n- /path2, no explanations."
            )
            response_text = self._ask_gemini(prompt)
            if response_text:
                dynamic_paths = [path.strip('- ').strip() for path in response_text.split('\n') if path.strip()]
                if not self.quiet:
                    print(f"[*] Generated {len(dynamic_paths)} dynamic AI-suggested paths based on findings")
                return dynamic_paths
            return []
        except Exception as e:
            print(f"[!] Error generating dynamic paths with Gemini: {e}")
            return []

    def test_endpoint(self, path, method, follow_redirects=False, custom_payload=None, ai_analysis=False):
        """Test single endpoint with comprehensive error handling and optional AI analysis"""
        if not self.running:
            return
            
        url = urljoin(self.base_url, path)
        
        try:
            # Prepare request parameters
            request_kwargs = {
                'timeout': self.timeout,
                'allow_redirects': follow_redirects
            }
            
            # Add payload for methods that typically send data
            if method in ['POST', 'PUT', 'PATCH']:
                if custom_payload:
                    request_kwargs['json'] = custom_payload
                else:
                    request_kwargs['json'] = {}
            
            # Send request based on method
            if method == 'GET':
                resp = self.session.get(url, **request_kwargs)
            elif method == 'POST':
                resp = self.session.post(url, **request_kwargs)
            elif method == 'PUT':
                resp = self.session.put(url, **request_kwargs)
            elif method == 'DELETE':
                resp = self.session.delete(url, **request_kwargs)
            elif method == 'PATCH':
                resp = self.session.patch(url, **request_kwargs)
            elif method == 'HEAD':
                resp = self.session.head(url, **request_kwargs)
            elif method == 'OPTIONS':
                resp = self.session.options(url, **request_kwargs)
            else:
                resp = self.session.request(method, url, **request_kwargs)
            
            status = resp.status_code
            content_length = len(resp.content)
            content_type = resp.headers.get('content-type', 'Unknown')
            server = resp.headers.get('server', 'Unknown')
            
            # Capture redirect information if following redirects
            redirect_location = None
            if follow_redirects and resp.history:
                redirect_location = resp.url
            
            with self.lock:
                self.completed += 1
            
            # Check for interesting responses
            if status in self.interesting_codes:
                endpoint_info = {
                    'method': method,
                    'url': url,
                    'path': path,
                    'status': status,
                    'length': content_length,
                    'content_type': content_type,
                    'server': server,
                    'redirect_location': redirect_location,
                    'ai_analysis': None
                }
                
                # AI analysis if enabled
                if ai_analysis and self.gemini_model:
                    snippet = resp.text[:500]  # Truncate for privacy/prompt limits
                    prompt = (
                        "Analyze this API response for security implications. Structure output as:\n"
                        "- Vulnerability: [Type or None]\n"
                        "- Severity: [Low/Medium/High/Critical]\n"
                        "- Explanation: [Brief description, check for PII, API keys, SQLi, XSS, IDOR, etc.]\n"
                        "- Suggestions: [Auth needs, parameters, or follow-ups]\n\n"
                        "Example:\n- Vulnerability: Sensitive Data Exposure\n- Severity: High\n- Explanation: Response contains unredacted email addresses.\n- Suggestions: Test with auth headers.\n\n"
                        f"Details: URL={url}, Method={method}, Status={status}, Content-Type={content_type}, Response Snippet={snippet}."
                    )
                    ai_analysis_result = self._ask_gemini(prompt)
                    if ai_analysis_result:
                        endpoint_info['ai_analysis'] = ai_analysis_result
                
                with self.lock:
                    self.found_endpoints.append(endpoint_info)
                
                if not self.quiet:
                    color = '\033[92m' if status == 200 else '\033[93m' if status in [401, 403] else '\033[91m' if status in [500, 502, 503] else '\033[94m' if status in [301, 302, 307, 308] else '\033[95m' if status in [400, 422] else '\033[91m' if status == 429 else '\033[96m'
                    redirect_info = f" -> {redirect_location}" if redirect_location else ""
                    print(f"\n{color}[{status}] {method:<7} {url} ({content_length} bytes) {content_type}{redirect_info}\033[0m")
                    if endpoint_info['ai_analysis']:
                        print(f"      AI Analysis: {endpoint_info['ai_analysis'][:100]}...")  # Truncated preview
            
            elif status != 404 and not self.quiet:
                print(f"\n[{status}] {method:<7} {url} (Unusual response)")
            
            # Dynamic rate limit handling for target API
            if status == 429:
                with self.lock:
                    if self.delay == 0:
                        self.delay = 1
                    else:
                        self.delay *= 2
                    logging.warning(f"Rate limit detected (429) at {url}. Increasing delay to {self.delay} seconds.")
            
            # Rate limiting delay
            if self.delay > 0:
                time.sleep(self.delay)
                
        except requests.exceptions.Timeout:
            with self.lock:
                self.completed += 1
            logging.debug(f"Timeout for {method} {url}")
        except requests.exceptions.ConnectionError:
            with self.lock:
                self.completed += 1
            logging.debug(f"Connection error for {method} {url}")
        except Exception as e:
            with self.lock:
                self.completed += 1
            logging.debug(f"Unexpected error for {method} {url}: {e}")

    def progress_indicator(self):
        """Dedicated progress indicator thread with improved formatting"""
        last_line_length = 0
        while self.running and self.completed < self.total:
            with self.lock:
                if self.total > 0:
                    progress = (self.completed / self.total) * 100
                    found_count = len(self.found_endpoints)
                else:
                    progress = 0
                    found_count = 0
            
            if not self.quiet:
                progress_line = f"[*] Progress: {progress:.1f}% ({self.completed}/{self.total}) - Found: {found_count}"
                print(f"\r{' ' * last_line_length}\r{progress_line}", end='', flush=True)
                last_line_length = len(progress_line)
            
            time.sleep(0.5)

    def discover(self, wordlist_file=None, methods=['GET', 'POST'], follow_redirects=False, custom_payload=None, ai_paths_count=0, ai_analysis=False, ai_dynamic=False):
        """Main discovery function with enhanced AI features"""
        if not self.quiet:
            print(f"[*] Target: {self.base_url}")
            print(f"[*] Methods: {', '.join(methods)}")
            print(f"[*] Threads: {self.threads}")
            print(f"[*] Follow redirects: {follow_redirects}")
            if custom_payload:
                print(f"[*] Custom payload: {custom_payload}")
            if ai_paths_count > 0:
                print(f"[*] Generating {ai_paths_count} AI-suggested paths")
            if ai_analysis:
                print(f"[*] AI response analysis enabled")
            if ai_dynamic:
                print(f"[*] AI dynamic path augmentation enabled")
        
        paths = self.load_wordlist(wordlist_file)
        
        # Generate and add initial AI paths if requested
        if ai_paths_count > 0 and self.gemini_model:
            ai_paths = self.generate_ai_paths(ai_paths_count)
            paths = list(set(paths + ai_paths))  # Deduplicate
        
        self.total = len(paths) * len(methods)
        
        if self.total == 0:
            print("[!] No requests to make (empty wordlist or methods)")
            return []
        
        if not self.quiet:
            print(f"[*] Loaded {len(paths)} paths (including AI-generated)")
            print(f"[*] Total requests: {self.total}")
            print()
        
        # Start progress indicator thread
        progress_thread = threading.Thread(target=self.progress_indicator, daemon=True)
        progress_thread.start()
        
        # Initial scan
        self._run_scan(paths, methods, follow_redirects, custom_payload, ai_analysis)
        
        # Dynamic augmentation if enabled
        if ai_dynamic and self.gemini_model and self.found_endpoints:
            found_patterns = [f"{ep['method']} {ep['path']}" for ep in self.found_endpoints]
            dynamic_paths = self.generate_dynamic_paths(found_patterns)
            if dynamic_paths:
                dynamic_paths = list(set(dynamic_paths) - set([ep['path'] for ep in self.found_endpoints]))  # Avoid duplicates
                if dynamic_paths:
                    self.total += len(dynamic_paths) * len(methods)
                    if not self.quiet:
                        print(f"\n[*] Starting second pass with {len(dynamic_paths)} dynamic paths")
                    self._run_scan(dynamic_paths, methods, follow_redirects, custom_payload, ai_analysis)
        
        self.running = False
        
        if not self.quiet:
            print(f"\n\n[*] Scan completed!")
            print(f"[*] Found {len(self.found_endpoints)} interesting endpoints")
        
        return self.found_endpoints

    def _run_scan(self, paths, methods, follow_redirects, custom_payload, ai_analysis):
        """Helper to run a scan pass"""
        try:
            if self.threads == 1:
                for path in paths:
                    for method in methods:
                        if not self.running:
                            break
                        self.test_endpoint(path, method, follow_redirects, custom_payload, ai_analysis)
            else:
                with ThreadPoolExecutor(max_workers=self.threads) as executor:
                    futures = []
                    for path in paths:
                        for method in methods:
                            if not self.running:
                                break
                            future = executor.submit(self.test_endpoint, path, method, follow_redirects, custom_payload, ai_analysis)
                            futures.append(future)
                    
                    for future in as_completed(futures):
                        if not self.running:
                            break
                        try:
                            future.result()
                        except Exception as e:
                            logging.debug(f"Future execution error: {e}")
        
        except KeyboardInterrupt:
            self.running = False
            print(f"\n[!] Scan interrupted by user")

    def generate_report(self, output_file=None, output_format='text', ai_summary=False):
        """Generate comprehensive reports with multiple formats and optional AI summary"""
        if not self.found_endpoints:
            if not self.quiet:
                print("[*] No interesting endpoints found")
            return
        
        if not self.quiet:
            print("\n" + "="*70)
            print("DISCOVERED ENDPOINTS SUMMARY")
            print("="*70)
        
        # Sort by status code, then method for better organization
        sorted_endpoints = sorted(self.found_endpoints, key=lambda x: (x['status'], x['method']))
        
        if not self.quiet:
            for endpoint in sorted_endpoints:
                print(f"[{endpoint['status']}] {endpoint['method']:<7} {endpoint['url']}")
                print(f"      Content-Type: {endpoint['content_type']}")
                print(f"      Content-Length: {endpoint['length']} bytes")
                print(f"      Server: {endpoint['server']}")
                if endpoint.get('redirect_location'):
                    print(f"      Redirected to: {endpoint['redirect_location']}")
                if endpoint.get('ai_analysis'):
                    print(f"      AI Analysis:\n{endpoint['ai_analysis']}")
                print()
        
        # AI summary if enabled
        ai_summary_text = None
        if ai_summary and self.gemini_model:
            # Summarize if too many endpoints
            if len(sorted_endpoints) > 20:
                summary_prompt = (
                    f"Summarize these {len(sorted_endpoints)} endpoints into key themes and top 10 examples: "
                    f"{'\n'.join([f'- {ep['method']} {ep['url']} (Status: {ep['status']})' for ep in sorted_endpoints[:50]])}. "
                    "Output as a concise paragraph."
                )
                endpoints_summary = self._ask_gemini(summary_prompt) or '\n'.join([f"- {ep['method']} {ep['url']} (Status: {ep['status']})" for ep in sorted_endpoints[:20]])
            else:
                endpoints_summary = '\n'.join([f"- {ep['method']} {ep['url']} (Status: {ep['status']}, AI Analysis: {ep.get('ai_analysis', 'None')[:100]}...)" for ep in sorted_endpoints])
            
            prompt = (
                f"Here are discovered API endpoints: {endpoints_summary}\n\n"
                "Provide a high-level summary in sections:\n"
                "- Overview: [Key stats and themes]\n"
                "- Potential Risks: [List vulns with severity]\n"
                "- Top Priorities: [3-5 critical endpoints with reasons]\n"
                "Prioritize based on severity and impact."
            )
            ai_summary_text = self._ask_gemini(prompt)
            if ai_summary_text:
                if not self.quiet:
                    print("\n" + "="*70)
                    print("AI-GENERATED SUMMARY & RECOMMENDATIONS")
                    print("="*70)
                    print(ai_summary_text)
                    print("="*70 + "\n")

        # Save to file if specified
        if output_file:
            try:
                if output_format.lower() == 'json':
                    import json
                    from datetime import datetime
                    
                    report_data = {
                        'scan_info': {
                            'target': self.base_url,
                            'timestamp': datetime.now().isoformat(),
                            'total_found': len(self.found_endpoints),
                            'total_requests': self.total,
                            'ai_summary': ai_summary_text
                        },
                        'endpoints': sorted_endpoints
                    }
                    
                    with open(output_file, 'w') as f:
                        json.dump(report_data, f, indent=2)
                        
                elif output_format.lower() == 'csv':
                    import csv
                    
                    with open(output_file, 'w', newline='') as f:
                        writer = csv.writer(f)
                        writer.writerow(['Status', 'Method', 'URL', 'Path', 'Content-Type', 'Content-Length', 'Server', 'Redirect-Location', 'AI-Analysis'])
                        
                        for endpoint in sorted_endpoints:
                            writer.writerow([
                                endpoint['status'],
                                endpoint['method'],
                                endpoint['url'],
                                endpoint['path'],
                                endpoint['content_type'],
                                endpoint['length'],
                                endpoint['server'],
                                endpoint.get('redirect_location', ''),
                                endpoint.get('ai_analysis', '')
                            ])
                else:
                    # Enhanced text format
                    with open(output_file, 'w') as f:
                        f.write("API Endpoint Discovery Report\n")
                        f.write("="*50 + "\n")
                        f.write(f"Target: {self.base_url}\n")
                        f.write(f"Total Requests: {self.total}\n")
                        f.write(f"Endpoints Found: {len(self.found_endpoints)}\n")
                        f.write(f"Scan Date: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                        
                        for endpoint in sorted_endpoints:
                            f.write(f"[{endpoint['status']}] {endpoint['method']} {endpoint['url']}\n")
                            f.write(f"    Content-Type: {endpoint['content_type']}\n")
                            f.write(f"    Content-Length: {endpoint['length']} bytes\n")
                            f.write(f"    Server: {endpoint['server']}\n")
                            if endpoint.get('redirect_location'):
                                f.write(f"    Redirected to: {endpoint['redirect_location']}\n")
                            if endpoint.get('ai_analysis'):
                                f.write(f"    AI Analysis:\n{endpoint['ai_analysis']}\n")
                            f.write("\n")
                        
                        if ai_summary_text:
                            f.write("\n" + "="*50 + "\n")
                            f.write("AI-GENERATED SUMMARY & RECOMMENDATIONS\n")
                            f.write("="*50 + "\n")
                            f.write(ai_summary_text)
                            f.write("\n")
                
                if not self.quiet:
                    print(f"[*] Report saved to: {output_file}")
                    
            except Exception as e:
                print(f"[!] Error saving report: {e}")

def signal_handler(sig, frame):
    """Handle Ctrl+C gracefully - use exit code 1 for interruption"""
    print(f"\n[!] Interrupted by user. Exiting…")
    sys.exit(1)

def parse_headers(header_list):
    """Parse custom headers from command line arguments"""
    headers = {}
    if header_list:
        for header in header_list:
            if ':' in header:
                key, value = header.split(':', 1)
                headers[key.strip()] = value.strip()
            else:
                print(f"[!] Warning: Invalid header format '{header}' (use 'Key: Value')")
    return headers

def parse_payload(payload_str):
    """Parse custom payload from JSON string"""
    if not payload_str:
        return None

    try:
        import json
        return json.loads(payload_str)
    except json.JSONDecodeError as e:
        print(f"[!] Error parsing payload JSON: {e}")
        sys.exit(1)

def validate_url(url):
    """Validate and normalize URL format"""
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        print("[!] Error: Invalid URL format. Please include http:// or https://")
        sys.exit(1)
    return url

def setup_logging(verbose=False):
    """Setup logging configuration"""
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[logging.StreamHandler()] if verbose else [logging.NullHandler()]
    )

def main():
    # Set up signal handler for graceful exit
    signal.signal(signal.SIGINT, signal_handler)

    parser = argparse.ArgumentParser(
        description='API Endpoint Discovery Tool with Advanced AI Integration - Production Ready',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:

# Basic discovery with AI-enhanced wordlist and analysis (provide your Gemini key)
python api_discovery.py https://api.example.com --gemini-key YOUR_GEMINI_API_KEY --ai-paths 50 --ai-analysis --ai-summary

# Advanced scan with auth, dynamic augmentation, and full AI features
python api_discovery.py https://api.example.com \
    -H "Authorization: Bearer eyJ…" \
    -t 15 -d 0.1 -o results.json --format json \
    --gemini-key YOUR_GEMINI_API_KEY --ai-paths 100 --ai-analysis --ai-dynamic --ai-summary --gemini-concurrency 10

# Stealth mode with custom wordlist, AI analysis, and report summary
python api_discovery.py https://api.example.com \
    -w custom_api_paths.txt -t 1 -d 0.5 --quiet \
    --gemini-key YOUR_GEMINI_API_KEY --ai-analysis --ai-summary

# Comprehensive scan with all methods, redirects, and AI
python api_discovery.py https://api.example.com \
    -m GET POST PUT DELETE PATCH OPTIONS \
    --follow-redirects --payload '{"test":"data"}' \
    -o comprehensive_report.csv --format csv \
    --gemini-key YOUR_GEMINI_API_KEY --ai-paths 100 --ai-analysis --ai-dynamic --ai-summary --gemini-model gemini-2.5-pro

# Scan through a proxy with AI
python api_discovery.py https://api.example.com --proxy http://localhost:8080 --gemini-key YOUR_GEMINI_API_KEY --ai-paths 50 --ai-analysis

Note: AI features use Google's Gemini API via free tier in AI Studio (with limits: e.g., 10 RPM for Gemini 2.5 Flash). For higher usage, upgrade tiers via billing. See https://ai.google.dev/gemini-api/docs/rate-limits for details. Use --gemini-concurrency to tune AI call parallelism.

Security Note: Use only on authorized targets. Ensure you have permission
before scanning any API endpoints.
"""
    )

    parser.add_argument('url', help='Target base URL (e.g., https://api.example.com)')
    parser.add_argument('-w', '--wordlist', help='Custom wordlist file (auto-downloads SecLists if not provided)')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of threads (default: 10, use 1 for stealth)')
    parser.add_argument('-T', '--timeout', type=int, default=5, help='Request timeout in seconds (default: 5)')
    parser.add_argument('-d', '--delay', type=float, default=0, help='Delay between requests in seconds (default: 0)')
    parser.add_argument('-m', '--methods', nargs='+', default=['GET', 'POST'], 
                        help='HTTP methods to test (default: GET POST)')
    parser.add_argument('-H', '--headers', nargs='*', 
                        help='Custom headers (e.g., "Authorization: Bearer TOKEN" "X-API-Key: KEY")')
    parser.add_argument('-p', '--payload', help='Custom JSON payload for POST/PUT/PATCH requests')
    parser.add_argument('-o', '--output', help='Output file for results')
    parser.add_argument('-f', '--format', choices=['text', 'json', 'csv'], default='text', 
                        help='Output format (default: text)')
    parser.add_argument('-q', '--quiet', action='store_true', help='Quiet mode (minimal output)')
    parser.add_argument('--follow-redirects', action='store_true', help='Follow HTTP redirects')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose logging for debugging')
    parser.add_argument('--proxy', help='Proxy URL (e.g., http://localhost:8080)')
    parser.add_argument('--gemini-key', help='Google Gemini API key for AI features')
    parser.add_argument('--gemini-model', default='gemini-2.5-flash', help='Gemini model to use (default: gemini-2.5-flash; alternatives: gemini-2.5-pro)')
    parser.add_argument('--gemini-concurrency', type=int, default=5, help='Max concurrent Gemini API calls (default: 5; tune for rate limits)')
    parser.add_argument('--ai-paths', type=int, default=0, help='Number of initial AI-generated paths to add (default: 0)')
    parser.add_argument('--ai-analysis', action='store_true', help='Enable AI analysis of interesting responses')
    parser.add_argument('--ai-dynamic', action='store_true', help='Enable dynamic AI path augmentation after initial scan')
    parser.add_argument('--ai-summary', action='store_true', help='Enable AI summarization in report')

    args = parser.parse_args()

    # Setup logging
    setup_logging(args.verbose)

    # Validate URL
    validated_url = validate_url(args.url)

    # Parse custom headers
    custom_headers = parse_headers(args.headers)

    # Parse custom payload
    custom_payload = parse_payload(args.payload)

    # Initialize discovery with Gemini key and model
    discovery = APIDiscovery(
        base_url=validated_url,
        threads=args.threads,
        timeout=args.timeout,
        delay=args.delay,
        quiet=args.quiet,
        custom_headers=custom_headers,
        proxy=args.proxy,
        gemini_api_key=args.gemini_key or os.getenv('GEMINI_API_KEY'),  # Fallback to env var
        gemini_model_name=args.gemini_model,
        gemini_concurrency=args.gemini_concurrency
    )

    # Run discovery
    try:
        endpoints = discovery.discover(
            wordlist_file=args.wordlist,
            methods=[m.upper() for m in args.methods],
            follow_redirects=args.follow_redirects,
            custom_payload=custom_payload,
            ai_paths_count=args.ai_paths,
            ai_analysis=args.ai_analysis,
            ai_dynamic=args.ai_dynamic
        )
        
        # Generate report
        discovery.generate_report(
            output_file=args.output, 
            output_format=args.format,
            ai_summary=args.ai_summary
        )
        
    except Exception as e:
        logging.exception(f"Error during discovery: {e}")
        print(f"[!] Error during discovery: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
