import requests
import argparse
import json
import csv
import threading
import queue
import time
import logging
import sys
import os
import random
from urllib.parse import urljoin, urlparse
from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter
from typing import Dict, List, Any, Optional
import google.generativeai as genai

# Set up logging with console and file output
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)  # Console output
    ]
)
logger = logging.getLogger(__name__)

class APIDiscovery:
    INTERESTING_CODES = {200, 201, 202, 204, 301, 302, 307, 308, 400, 401, 403, 405, 422, 429, 500, 502, 503}

    USER_AGENTS = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36',
        'Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Mobile/15E148 Safari/604.1',
        'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
        'PostmanRuntime/7.28.4',
        'curl/7.68.0'
    ]

    def __init__(self, args: argparse.Namespace) -> None:
        """
        Initialize the API Discovery tool with provided arguments.

        :param args: Parsed command-line arguments.
        """
        self.args = args
        self.validate_url(args.url)
        self.config: Dict[str, Any] = self.load_config(args.config)
        self.validate_scope(args.url)
        self.session = requests.Session()

        if self.config:
            if 'methods' in self.config:
                self.args.methods = self.config['methods']
            if 'delay' in self.config:
                self.args.delay = self.config['delay']
            if 'headers' in self.config:
                self.args.headers = self.config['headers']
            if 'payload' in self.config:
                self.args.payload = json.dumps(self.config['payload'])
            if 'user_agents' in self.config:
                self.USER_AGENTS = self.config['user_agents']

        self.current_delay: float = args.delay
        self.timeout: int = args.timeout
        self.ai_paths: int = args.ai_paths
        self.ai_analysis: bool = args.ai_analysis
        self.ai_dynamic: bool = args.ai_dynamic
        self.ai_summary: bool = args.ai_summary
        if args.gemini_key:
            genai.configure(api_key=args.gemini_key)
            self.ai_model = genai.GenerativeModel('gemini-1.5-pro')
        else:
            self.ai_model = None
            if self.ai_analysis or self.ai_dynamic or self.ai_summary:
                logger.warning("AI features enabled but no Gemini key provided. Falling back to basic analysis.")

        self.setup_session()
        self.results: List[Dict[str, Any]] = []
        self.lock = threading.Lock()
        self.found_count: int = 0
        self.total_tasks: int = 0
        self.processed_tasks: int = 0
        self.stop_event = threading.Event()
        self.error_count: int = 0
        self.response_times: List[float] = []
        self.content_lengths: List[int] = []

        # Add file handler for logging
        file_handler = logging.FileHandler(args.log_file, mode='w')
        file_handler.setLevel(logging.INFO)
        file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        logger.addHandler(file_handler)
        logger.info(f"Logging to file: {args.log_file}")
        logger.info("All console output is captured in the log file for bug bounty reporting. Check this file for complete, untruncated details.")

        self.respect_robots_and_security(args.url)

    @staticmethod
    def validate_url(url: str) -> None:
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            raise ValueError(f"Invalid URL format: {url}")
        logger.info(f"Validated URL: {url}")

    def validate_scope(self, url: str) -> None:
        allowed_domains = self.config.get('allowed_domains', [])
        if allowed_domains:
            parsed = urlparse(url)
            if parsed.netloc not in allowed_domains:
                raise ValueError(f"URL {url} is out of scope. Allowed domains: {allowed_domains}")
        logger.info("Scope validation passed (placeholder - enhance with real API integration)")

    def setup_session(self) -> None:
        if self.args.proxy:
            proxies = {'http': self.args.proxy, 'https': self.args.proxy}
            self.session.proxies.update(proxies)
            logger.info(f"Using proxy: {self.args.proxy}")

        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy, pool_connections=10, pool_maxsize=10)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

        self.session.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'})
        for header in self.args.headers:
            if ':' not in header:
                logger.error(f"Skipping invalid header format: {header}")
                continue
            key, value = header.split(':', 1)
            self.session.headers.update({key.strip(): value.strip()})

    def get_random_user_agent(self) -> str:
        return random.choice(self.USER_AGENTS)

    def load_wordlist(self) -> List[str]:
        wordlist = []
        try:
            with open(self.args.wordlist, 'r') as file:
                wordlist = [line.strip() for line in file if line.strip()]
        except FileNotFoundError:
            logger.error(f"Wordlist file not found: {self.args.wordlist}")
            sys.exit(1)

        if self.ai_dynamic and self.ai_model:
            ai_paths = self.generate_ai_paths()
            wordlist.extend(ai_paths[:self.ai_paths])
            logger.info(f"Added {len(ai_paths[:self.ai_paths])} AI-generated paths to wordlist")
        
        if not wordlist:
            raise ValueError("Wordlist is empty and no AI paths generated")
        return wordlist

    def load_config(self, config_file: Optional[str]) -> Dict[str, Any]:
        if config_file and os.path.exists(config_file):
            try:
                with open(config_file, 'r') as f:
                    config = json.load(f)
                logger.info(f"Loaded configuration from {config_file}")
                return config
            except json.JSONDecodeError:
                logger.error(f"Invalid JSON in config file: {config_file}")
                return {}
        return {}

    def generate_ai_paths(self) -> List[str]:
        if not self.ai_model:
            return []
        for attempt in range(3):
            try:
                prompt = (
                    f"Generate {self.ai_paths} common API endpoint paths for a social networking application like Bumble. "
                    f"Include paths for user profiles, authentication, admin functions, and settings, similar to those in *Hacking APIs* (Pages 151–181). "
                    f"Return paths as a list of strings, one per line."
                )
                response = self.ai_model.generate_content(prompt)
                paths = response.text.strip().split('\n')
                return [path.strip() for path in paths if path.strip()]
            except Exception as e:
                if "429" in str(e):
                    retry_delay = 18  # Default retry delay from log
                    logger.warning(f"Gemini API quota exceeded, retrying in {retry_delay}s (attempt {attempt + 1}/3)")
                    time.sleep(retry_delay)
                else:
                    logger.error(f"Error generating AI paths: {e}")
                    return []
        logger.error("Failed to generate AI paths after 3 attempts")
        return []

    def respect_robots_and_security(self, base_url: str) -> None:
        robots_url = urljoin(base_url, '/robots.txt')
        try:
            response = self.session.get(robots_url, timeout=self.timeout)
            if response.status_code == 200:
                if 'Crawl-delay' in response.text:
                    delay_line = [line for line in response.text.splitlines() if 'Crawl-delay' in line][0]
                    self.current_delay = max(self.current_delay, float(delay_line.split(':')[1].strip()))
                    logger.info(f"Adjusted delay based on robots.txt: {self.current_delay}s")
                if 'Disallow: /' in response.text:
                    logger.warning("robots.txt disallows all crawling. Proceed with caution.")
            logger.info(f"robots.txt response: Status {response.status_code}, Headers: {dict(response.headers)}, Body: {response.text[:1000]}")
        except Exception as e:
            logger.info(f"Could not fetch robots.txt: {e}")

        security_url = urljoin(base_url, '/.well-known/security.txt')
        try:
            response = self.session.get(security_url, timeout=self.timeout)
            if response.status_code == 200:
                logger.info(f"security.txt found: {response.text[:1000]}... | Headers: {dict(response.headers)}")
            else:
                logger.info(f"security.txt response: Status {response.status_code}, Headers: {dict(response.headers)}")
        except Exception as e:
            logger.info(f"Could not fetch security.txt: {e}")

    def handle_rate_limit(self, response: requests.Response, url: str) -> None:
        if response.status_code == 429:
            retry_after = response.headers.get('Retry-After')
            headers = dict(response.headers)
            if retry_after:
                try:
                    delay = int(retry_after)
                    logger.warning(f"Rate limited at {url}. Waiting {delay}s as suggested by server | Headers: {headers}")
                    time.sleep(delay)
                    return
                except ValueError:
                    pass
            
            self.current_delay *= 1.5
            logger.warning(f"Rate limit detected at {url}. Increasing delay to {self.current_delay:.2f}s | Headers: {headers}")

    def adaptive_delay(self, response_time: float, was_error: bool) -> None:
        if was_error:
            self.error_count += 1
        error_rate = self.error_count / max(1, self.processed_tasks)
        if error_rate > 0.1:
            self.current_delay *= 1.2
            logger.info(f"Increasing delay due to high error rate: {self.current_delay:.2f}s")
        elif response_time > 2.0:
            self.current_delay += 0.1
            logger.info(f"Increasing delay due to slow response: {self.current_delay:.2f}s")

    def get_evasion_headers(self, waf_type: str) -> Dict[str, str]:
        evasion_patterns = {
            'cloudflare': {
                'CF-Connecting-IP': '127.0.0.1',
                'X-Forwarded-For': '127.0.0.1'
            },
            'aws': {
                'X-Real-IP': '127.0.0.1',
                'X-Originating-IP': '127.0.0.1'
            }
        }
        headers = evasion_patterns.get(waf_type, {})
        logger.info(f"Evasion headers for {waf_type}: {headers}")
        return headers

    def detect_waf_cdn(self, response: requests.Response) -> str:
        headers = {k.lower(): v.lower() for k, v in response.headers.items()}
        waf_indicators = {
            'cloudflare': ['cf-ray', 'cloudflare'],
            'akamai': ['akamai-ghost'],
            'aws': ['x-amz-request-id'],
            'fastly': ['fastly-debug-digest']
        }
        for waf, indicators in waf_indicators.items():
            for indicator in indicators:
                if any(indicator in key or indicator in value for key, value in headers.items()):
                    return waf
        return 'unknown'

    def analyze_response_patterns(self) -> Dict[str, Any]:
        if not self.response_times:
            return {'average_time': 0, 'std_dev_time': 0, 'average_length': 0, 'std_dev_length': 0}
        
        import statistics
        avg_time = statistics.mean(self.response_times)
        std_time = statistics.stdev(self.response_times) if len(self.response_times) > 1 else 0
        avg_length = statistics.mean(self.content_lengths)
        std_length = statistics.stdev(self.content_lengths) if len(self.content_lengths) > 1 else 0
        return {
            'average_time': avg_time,
            'std_dev_time': std_time,
            'average_length': avg_length,
            'std_dev_length': std_length
        }

    def analyze_content(self, response: requests.Response) -> Dict[str, Any]:
        content = response.text.lower()
        analysis = {
            'type': 'unknown',
            'framework': None,
            'versioning': None,
            'error_pattern': None,
            'cors': 'cors' in response.headers.get('Access-Control-Allow-Origin', '').lower(),
            'waf_cdn': self.detect_waf_cdn(response),
            'vulnerability': 'None',
            'severity': 'None',
            'explanation': 'No analysis available'
        }

        if self.ai_analysis and self.ai_model:
            for attempt in range(3):
                try:
                    prompt = (
                        f"Analyze the following API response for security vulnerabilities based on *Hacking APIs* (Pages 82–95, 251–292):\n"
                        f"URL: {response.url}\nMethod: {response.request.method}\nStatus: {response.status_code}\n"
                        f"Content-Type: {response.headers.get('content-type', 'Unknown')}\nServer: {response.headers.get('server', 'Unknown')}\n"
                        f"Response Body: {content[:1000]}\n"
                        f"Provide a detailed analysis including: vulnerability type, severity (Low/Medium/High), and explanation referencing *Hacking APIs*."
                    )
                    ai_response = self.ai_model.generate_content(prompt)
                    ai_analysis = json.loads(ai_response.text) if ai_response.text.startswith('{') else {
                        'vulnerability': 'AI Analysis Error',
                        'severity': 'Unknown',
                        'explanation': f"AI failed to provide structured response: {ai_response.text}"
                    }
                    analysis.update(ai_analysis)
                    break
                except Exception as e:
                    if "429" in str(e):
                        retry_delay = 18  # Default retry delay from log
                        logger.warning(f"Gemini API quota exceeded, retrying in {retry_delay}s (attempt {attempt + 1}/3)")
                        time.sleep(retry_delay)
                    else:
                        logger.error(f"AI analysis failed: {e}")
                        analysis['vulnerability'] = 'AI Analysis Failed'
                        analysis['severity'] = 'Unknown'
                        analysis['explanation'] = f"Error during AI analysis: {str(e)}"
                        break
        else:
            if 'swagger' in content or 'openapi' in content:
                analysis['type'] = 'api_documentation'
                analysis['vulnerability'] = 'Information Disclosure (API Documentation Exposure)'
                analysis['severity'] = 'Low'
                analysis['explanation'] = (
                    f"The endpoint returns API documentation (Swagger/OpenAPI), which may expose sensitive endpoint details. "
                    f"Per *Hacking APIs* (Page 87), this could lead to excessive data exposure if not properly restricted."
                )
            elif 'unauthorized' in content or 'forbidden' in content:
                analysis['type'] = 'auth_required'
                analysis['vulnerability'] = 'None (Authentication Required)'
                analysis['severity'] = 'Informational'
                analysis['explanation'] = (
                    f"The endpoint requires authentication, as indicated by 'unauthorized' or 'forbidden' in the response. "
                    f"Further testing with valid credentials is needed to assess access controls (*Hacking APIs*, Pages 207–228)."
                )
            elif 'internal server error' in content:
                analysis['type'] = 'server_error'
                analysis['vulnerability'] = 'Server Error Exposure'
                analysis['severity'] = 'Medium'
                analysis['explanation'] = (
                    f"The endpoint returns an internal server error, potentially revealing backend details. "
                    f"This may indicate injection vulnerabilities or misconfigurations (*Hacking APIs*, Pages 277–292)."
                )
            elif response.headers.get('content-type', '').lower() == 'application/octet-stream' and response.status_code == 200:
                analysis['vulnerability'] = 'Unusual API Behavior / Misconfiguration'
                analysis['severity'] = 'Low'
                analysis['explanation'] = (
                    f"The endpoint returns a 200 status with 'application/octet-stream' Content-Type, which is unusual for an API. "
                    f"This may indicate a misconfiguration or non-standard behavior (*Hacking APIs*, Pages 82–95)."
                )

        server_header = response.headers.get('server', '').lower()
        powered_by = response.headers.get('x-powered-by', '').lower()
        if 'django' in server_header or 'django' in powered_by:
            analysis['framework'] = 'Django REST'
        elif 'flask' in server_header or 'flask' in powered_by:
            analysis['framework'] = 'Flask-RESTful'
        elif 'fastapi' in powered_by:
            analysis['framework'] = 'FastAPI'

        if '/v1/' in response.url or '/v2/' in response.url:
            analysis['versioning'] = 'detected'

        if 'stack trace' in content or 'exception' in content:
            analysis['error_pattern'] = 'reveals_backend'
            analysis['vulnerability'] = 'Information Disclosure (Backend Details)'
            analysis['severity'] = 'Medium'
            analysis['explanation'] = (
                f"The response contains stack traces or exceptions, revealing backend details. "
                f"This could aid attackers in exploiting vulnerabilities (*Hacking APIs*, Pages 277–292)."
            )

        return analysis

    def detect_auth_methods(self, response: requests.Response) -> List[str]:
        auth_methods = []
        www_auth = response.headers.get('WWW-Authenticate')
        if www_auth:
            auth_methods.append(www_auth)
        if 'jwt' in response.text.lower() or 'bearer' in response.text.lower():
            auth_methods.append('bearer_token')
        return auth_methods

    def check_known_vulnerabilities(self, endpoint: str, framework: Optional[str]) -> List[str]:
        vulnerabilities = []
        nvd_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={framework}+API"
        try:
            response = requests.get(nvd_url, timeout=self.timeout)
            if response.status_code == 200:
                data = response.json()
                for cve in data.get('vulnerabilities', [])[:5]:
                    vulnerabilities.append(cve['cve']['id'])
            logger.info(f"Checked vulnerabilities for {endpoint} ({framework}): {vulnerabilities}")
        except Exception as e:
            logger.error(f"Error checking vulnerabilities: {e}")
        return vulnerabilities

    def generate_summary(self) -> Dict[str, Any]:
        if not self.ai_summary or not self.ai_model:
            return {
                'total_endpoints': self.found_count,
                'summary': 'AI summary disabled or no Gemini key provided.'
            }
        
        for attempt in range(3):
            try:
                prompt = (
                    f"Generate a bug bounty report summary based on *Hacking APIs* (Pages 335–346). "
                    f"Total endpoints found: {self.found_count}. "
                    f"Sample findings: {json.dumps(self.results[:5], indent=2)}. "
                    f"Provide a concise summary highlighting key vulnerabilities, severities, and recommendations."
                )
                response = self.ai_model.generate_content(prompt)
                return {
                    'total_endpoints': self.found_count,
                    'summary': response.text
                }
            except Exception as e:
                if "429" in str(e):
                    retry_delay = 18
                    logger.warning(f"Gemini API quota exceeded, retrying in {retry_delay}s (attempt {attempt + 1}/3)")
                    time.sleep(retry_delay)
                else:
                    logger.error(f"Error generating AI summary: {e}")
                    return {
                        'total_endpoints': self.found_count,
                        'summary': f"Error generating summary: {str(e)}"
                    }
        logger.error("Failed to generate AI summary after 3 attempts")
        return {
            'total_endpoints': self.found_count,
            'summary': "Failed to generate AI summary due to repeated quota errors"
        }

    def discover_endpoints(self, task_queue: queue.Queue) -> None:
        """
        Discover API endpoints by processing tasks from the queue.

        :param task_queue: Queue containing (path, method) tuples.
        """
        while not task_queue.empty() and not self.stop_event.is_set():
            try:
                path, method = task_queue.get(timeout=1)
            except queue.Empty:
                continue

            url = urljoin(self.args.url, path)
            payload = json.loads(self.args.payload) if self.args.payload else None

            self.session.headers.update({'User-Agent': self.get_random_user_agent()})
            request_headers = dict(self.session.headers)

            try:
                delay = self.current_delay + random.uniform(-0.05, 0.05)
                time.sleep(max(0, delay))

                response = self.session.request(
                    method=method,
                    url=url,
                    json=payload,
                    allow_redirects=self.args.follow_redirects,
                    timeout=self.timeout
                )

                self.handle_rate_limit(response, url)
                self.adaptive_delay(response.elapsed.total_seconds(), False)
                self.response_times.append(response.elapsed.total_seconds())
                self.content_lengths.append(len(response.content))

                final_url = response.url if response.history else url
                response_headers = dict(response.headers)
                response_body = response.text

                if response.status_code in self.INTERESTING_CODES:
                    content_analysis = self.analyze_content(response)
                    auth_methods = self.detect_auth_methods(response)

                    if content_analysis['waf_cdn'] != 'unknown':
                        evasion_headers = self.get_evasion_headers(content_analysis['waf_cdn'])
                        self.session.headers.update(evasion_headers)
                        logger.info(f"Applied evasion headers for {content_analysis['waf_cdn']} | Headers: {evasion_headers}")

                    vulnerabilities = self.check_known_vulnerabilities(url, content_analysis['framework']) if content_analysis['framework'] else []

                    with self.lock:
                        result = {
                            'method': method,
                            'url': url,
                            'status': response.status_code,
                            'final_url': final_url,
                            'length': len(response.content),
                            'content_type': response_headers.get('content-type', 'Unknown'),
                            'server': response_headers.get('server', 'Unknown'),
                            'response_time': response.elapsed.total_seconds(),
                            'analysis': content_analysis,
                            'auth_methods': auth_methods,
                            'vulnerabilities': vulnerabilities,
                            'request_headers': request_headers,
                            'response_headers': response_headers,
                            'response_body': response_body
                        }
                        self.results.append(result)
                        self.found_count += 1
                        if not self.args.quiet:
                            logger.info(
                                f"[+] {method} {url} ({result['length']} bytes) {result['content_type']}\n"
                                f"      AI Analysis: - Vulnerability: {content_analysis.get('vulnerability', 'None')}\n"
                                f"      - Severity: {content_analysis.get('severity', 'None')}\n"
                                f"      - Explanation: {content_analysis.get('explanation', 'No analysis available')}\n"
                                f"      Auth: {auth_methods}\n"
                                f"      Vulns: {vulnerabilities}\n"
                                f"      Request Headers: {request_headers}\n"
                                f"      Response Headers: {response_headers}\n"
                                f"      Response Body: {response_body}"
                            )

                elif not self.args.quiet and response.status_code != 404:
                    logger.info(
                        f"[?] Interesting: {method} {url} (Status: {response.status_code}) | "
                        f"Request Headers: {request_headers} | Response Headers: {response_headers} | "
                        f"Response Body: {response_body}"
                    )

            except requests.RequestException as e:
                if not self.args.quiet:
                    logger.error(f"Error testing {method} {url}: {str(e)} | Request Headers: {request_headers}")
                self.adaptive_delay(0, True)

            finally:
                with self.lock:
                    self.processed_tasks += 1
                    if self.total_tasks > 0 and not self.args.quiet:
                        progress = (self.processed_tasks / self.total_tasks) * 100
                        logger.info(f"[*] Progress: {progress:.1f}% ({self.processed_tasks}/{self.total_tasks}) - Found: {self.found_count}")

                task_queue.task_done()

    def run(self) -> None:
        wordlist = self.load_wordlist()
        methods = self.args.methods

        task_queue = queue.Queue()

        for path in wordlist:
            for method in methods:
                task_queue.put((path, method))

        self.total_tasks = task_queue.qsize()

        logger.info(f"Starting discovery on {self.args.url} with {len(wordlist)} paths and {len(methods)} methods")
        logger.info(f"Total tasks: {self.total_tasks}")

        threads = []
        for _ in range(self.args.threads):
            t = threading.Thread(target=self.discover_endpoints, args=(task_queue,))
            t.daemon = True
            t.start()
            threads.append(t)

        try:
            task_queue.join()
        except KeyboardInterrupt:
            logger.info("Shutdown requested. Stopping threads...")
            self.stop_event.set()
            for t in threads:
                t.join(timeout=5)
            logger.info("Graceful shutdown complete.")

        self.stop_event.set()

        patterns = self.analyze_response_patterns()
        logger.info(f"Response patterns: {patterns}")

        if self.ai_summary:
            summary = self.generate_summary()
            logger.info(f"Bug Bounty Summary: {json.dumps(summary, indent=2)}")

        self.save_results()

    def save_results(self) -> None:
        if not self.args.output:
            return

        os.makedirs(os.path.dirname(self.args.output) or '.', exist_ok=True)

        if self.args.format == 'json':
            with open(self.args.output, 'w') as f:
                json.dump(self.results, f, indent=4)
        elif self.args.format == 'csv':
            fieldnames = ['method', 'url', 'status', 'final_url', 'length', 'content_type', 'server', 'response_time', 'analysis', 'auth_methods', 'vulnerabilities', 'request_headers', 'response_headers', 'response_body']
            with open(self.args.output, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(self.results)
        else:
            with open(self.args.output, 'w') as f:
                for result in self.results:
                    f.write(f"{result['method']} {result['url']} (Status: {result['status']}) -> {result['final_url']} | "
                            f"Length: {result['length']} | Type: {result['content_type']} | "
                            f"Server: {result['server']} | Time: {result['response_time']:.2f}s | "
                            f"Analysis: {result['analysis']} | Auth: {result['auth_methods']} | "
                            f"Vulns: {result['vulnerabilities']} | "
                            f"Request Headers: {request_headers} | "
                            f"Response Headers: {response_headers} | "
                            f"Response Body: {response_body}\n")

        logger.info(f"Results saved to {self.args.output} in {self.args.format} format")

def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Professional API Endpoint Discovery Tool",
        epilog="Ethical Use Only: Ensure you have explicit permission to scan the target. This tool is for authorized security testing only. "
               "For stealth testing, use --proxy with Tor (socks5://127.0.0.1:9050) where permitted. "
               "All console output is captured in the log file for complete details."
    )
    parser.add_argument("url", help="Base URL of the target API (e.g., https://api.example.com/)")
    parser.add_argument("wordlist", help="Path to the wordlist file")
    parser.add_argument("-m", "--methods", nargs='+', default=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'],
                        help="HTTP methods to test (default: all common methods)")
    parser.add_argument("-p", "--proxy", help="Proxy URL (e.g., http://127.0.0.1:8080 or socks5://127.0.0.1:9050 for Tor)")
    parser.add_argument("-H", "--headers", action='append', default=[],
                        help="Custom headers (e.g., -H 'Authorization: Bearer token') - can be used multiple times")
    parser.add_argument("--payload", default='{}', help="JSON payload for requests (default: empty object)")
    parser.add_argument("-t", "--threads", type=int, default=5, help="Number of threads (default: 5, use 1 for stealth)")
    parser.add_argument("-T", "--timeout", type=int, default=5, help="Request timeout in seconds (default: 5)")
    parser.add_argument("-d", "--delay", type=float, default=0.1, help="Initial delay between requests in seconds (default: 0.1)")
    parser.add_argument("--follow-redirects", action='store_true', help="Follow HTTP redirects")
    parser.add_argument("-o", "--output", help="Output file path")
    parser.add_argument("--format", choices=['text', 'json', 'csv'], default='text', help="Output format (default: text)")
    parser.add_argument("-q", "--quiet", action='store_true', help="Quiet mode - suppress progress output")
    parser.add_argument("--config", help="Path to configuration JSON file (can include allowed_domains for scope)")
    parser.add_argument("--log-file", default='api_discovery.log', help="Path to log file (default: api_discovery.log)")
    parser.add_argument("--gemini-key", help="Google Gemini API key for AI analysis")
    parser.add_argument("--ai-paths", type=int, default=0, help="Number of AI-generated paths to include (default: 0)")
    parser.add_argument("--ai-analysis", action='store_true', help="Enable AI-driven vulnerability analysis")
    parser.add_argument("--ai-dynamic", action='store_true', help="Enable AI-driven dynamic path generation")
    parser.add_argument("--ai-summary", action='store_true', help="Generate AI-driven summary for bug bounty report")
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_arguments()
    try:
        json.loads(args.payload)
    except json.JSONDecodeError:
        logger.error("Invalid JSON payload")
        sys.exit(1)
    discovery = APIDiscovery(args)
    discovery.run()
