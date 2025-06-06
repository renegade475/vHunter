import requests
import urllib.parse
import re
import json
import time
from bs4 import BeautifulSoup
from datetime import datetime

class VulnerabilityScanner:
    def __init__(self, target_url, threads=10, delay=0.5, timeout=15, log_callback=None):
        self.target_url = target_url.rstrip('/')
        self.base_domain = urllib.parse.urlparse(target_url).netloc
        self.threads = threads
        self.delay = delay
        self.timeout = timeout
        self.log_callback = log_callback or print

        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        })

        from requests.adapters import HTTPAdapter
        from urllib3.util.retry import Retry
        adapter = HTTPAdapter(max_retries=Retry(total=3, backoff_factor=1))
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

        self.vulnerabilities = []
        self.forms = []
        self.links = []
        self.max_forms_to_test = 10

    def log(self, msg):
        self.log_callback(msg)

    def log_vulnerability(self, vuln_type, severity, url, description, payload=None):
        vuln = {
            'type': vuln_type,
            'severity': severity,
            'url': url,
            'description': description,
            'payload': payload,
            'timestamp': datetime.now().isoformat()
        }
        self.vulnerabilities.append(vuln)
        self.log(f"[{severity}] {vuln_type} at {url}")
        if payload:
            self.log(f"    Payload: {payload}")
        self.log(f"    Description: {description}")

    def crawl_website(self):
        self.log(f"[INFO] Crawling {self.target_url}")
        visited = set()
        to_visit = [self.target_url]

        while to_visit and len(visited) < 30:
            url = to_visit.pop(0)
            if url in visited:
                continue
            try:
                res = self.session.get(url, timeout=self.timeout)
                visited.add(url)
                if res.status_code == 200:
                    soup = BeautifulSoup(res.text, 'html.parser')
                    for form in soup.find_all('form'):
                        data = self.extract_form_data(form, url)
                        if data:
                            self.forms.append(data)
                    for a in soup.find_all('a', href=True):
                        link = urllib.parse.urljoin(url, a['href'])
                        if self.base_domain in link and link not in visited:
                            to_visit.append(link)
                            self.links.append(link)
                time.sleep(self.delay)
            except Exception:
                continue
        self.log(f"[INFO] Crawl complete. Found {len(self.forms)} forms and {len(self.links)} links")

    def extract_form_data(self, form, base_url):
        action = form.get('action', '')
        method = form.get('method', 'GET').upper()
        url = urllib.parse.urljoin(base_url, action)
        inputs = []
        for tag in form.find_all(['input', 'textarea', 'select']):
            name = tag.get('name')
            if name:
                inputs.append({
                    'name': name,
                    'type': tag.get('type', 'text'),
                    'value': tag.get('value', '')
                })
        return {'url': url, 'method': method, 'inputs': inputs} if inputs else None

    def test_sql_injection(self):
        self.log("[INFO] Testing for SQL injection...")
        payloads = ["' OR '1'='1", "'; DROP TABLE users--"]
        patterns = [r"sql", r"mysql", r"error", r"syntax", r"ORA-"]

        for form in self.forms[:self.max_forms_to_test]:
            for payload in payloads:
                data = {inp['name']: payload for inp in form['inputs']}
                try:
                    if form['method'] == 'POST':
                        res = self.session.post(form['url'], data=data, timeout=self.timeout)
                    else:
                        res = self.session.get(form['url'], params=data, timeout=self.timeout)
                    if any(re.search(p, res.text, re.IGNORECASE) for p in patterns):
                        self.log_vulnerability("SQL Injection", "HIGH", form['url'], "SQL error pattern found", payload)
                        break
                except:
                    continue

    def test_xss(self):
        self.log("[INFO] Testing for XSS...")
        payloads = ["<script>alert('XSS')</script>"]
        for form in self.forms[:self.max_forms_to_test]:
            for payload in payloads:
                data = {inp['name']: payload for inp in form['inputs']}
                try:
                    if form['method'] == 'POST':
                        res = self.session.post(form['url'], data=data, timeout=self.timeout)
                    else:
                        res = self.session.get(form['url'], params=data, timeout=self.timeout)
                    if payload in res.text:
                        self.log_vulnerability("Reflected XSS", "MEDIUM", form['url'], "Payload reflected in response", payload)
                        break
                except:
                    continue

    def generate_report(self, output_file=None):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = output_file or f"vuln_report_{timestamp}.json"
        report = {
            'scan_info': {
                'target': self.target_url,
                'timestamp': datetime.now().isoformat(),
                'total_vulnerabilities': len(self.vulnerabilities),
                'severity': {
                    'HIGH': sum(1 for v in self.vulnerabilities if v['severity'] == 'HIGH'),
                    'MEDIUM': sum(1 for v in self.vulnerabilities if v['severity'] == 'MEDIUM'),
                    'LOW': sum(1 for v in self.vulnerabilities if v['severity'] == 'LOW'),
                }
            },
            'vulnerabilities': self.vulnerabilities,
            'forms_found': len(self.forms),
            'links_found': len(self.links)
        }
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        self.log(f"[INFO] Report saved to {output_file}")
        return report

    def run_scan(self):
        self.log("[INFO] Starting scan...\n")
        self.crawl_website()
        self.test_sql_injection()
        self.test_xss()
        return self.generate_report()
