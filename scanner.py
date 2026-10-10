import asyncio
import re
import time
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse, parse_qs

import httpx
from bs4 import BeautifulSoup

from dom_analyzer import analyze_dom
from fingerprint import fingerprint_target
from logger import log
from payloads import build_payload_set

MISSING_HEADER_RULES = {
    'content-security-policy': (
        'Missing Security Header: Content-Security-Policy',
        'Without CSP the browser cannot restrict script sources, which increases XSS impact.',
        "Deploy a strict Content-Security-Policy header (e.g. default-src 'self').",
    ),
    'x-frame-options': (
        'Missing Security Header: X-Frame-Options',
        'Pages can be framed by third-party sites, enabling clickjacking attacks.',
        'Send X-Frame-Options: DENY or SAMEORIGIN (or use CSP frame-ancestors).',
    ),
    'strict-transport-security': (
        'Missing Security Header: Strict-Transport-Security',
        'Clients may downgrade to plain HTTP, exposing sessions to interception.',
        'Enable HSTS with a max-age of at least 31536000 seconds.',
    ),
}

REFERENCE_LINKS = {
    'xss': [
        'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html',
        'https://portswigger.net/web-security/cross-site-scripting',
    ],
    'sqli': [
        'https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html',
        'https://portswigger.net/web-security/sql-injection',
    ],
    'cve': ['https://nvd.nist.gov/', 'https://cve.mitre.org/'],
    'missing_header': [
        'https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP',
        'https://owasp.org/www-project-secure-headers/',
    ],
    'dom_xss': [
        'https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html',
        'https://portswigger.net/web-security/cross-site-scripting/dom-based',
    ],
}

WAF_SIGNATURES = {
    'cloudflare': ['cloudflare', 'cf-ray'],
    'modsecurity': ['mod_security', 'modsecurity'],
    'akamai': ['akamai'],
    'imperva': ['imperva', 'incapsula'],
    'f5': ['f5', 'big-ip'],
}


class VulnerabilityScanner:
    """Asynchronous web application vulnerability scanner."""

    def __init__(self, target_url: str, socketio=None,
                 auth_type: Optional[str] = None, auth_value: Optional[str] = None,
                 payload_mode: str = 'standard',
                 custom_wordlist: Optional[List[str]] = None) -> None:
        self.target_url = target_url
        self.socketio = socketio
        self.payload_mode = payload_mode
        self.custom_wordlist = custom_wordlist or []
        self.start_time = time.time()
        self.results: List[Dict[str, Any]] = []
        self.tech_stack: List[str] = []
        self.total_targets = 0
        self.completed_targets = 0
        self.waf_detected = False
        self.waf_vendor: Optional[str] = None
        self.active_payloads: List[str] = []

        self.headers = {'User-Agent': 'Mozilla/5.0 (compatible; SecAuditPro/1.5)'}
        if auth_type == 'cookie' and auth_value:
            self.headers['Cookie'] = auth_value.strip()
        elif auth_type == 'bearer' and auth_value:
            self.headers['Authorization'] = f"Bearer {auth_value.strip()}"

        self.sqli_payloads = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' UNION SELECT NULL --",
        ]
        self.sql_error_pattern = re.compile(
            r"SQL syntax.*?MySQL|Warning.*?mysqli?_|PostgreSQL.*?ERROR|ORA-\d{5}|"
            r"Microsoft OLE DB|Unclosed quotation mark",
            re.IGNORECASE,
        )

    def emit_log(self, message: str, level: str = 'info') -> None:
        log.info(message)
        if self.socketio is not None:
            self.socketio.emit('scan_log', {'msg': message, 'level': level})

    def emit_progress(self, message: str = '') -> None:
        if self.socketio is not None:
            self.socketio.emit('scan_progress', {
                'current': self.completed_targets,
                'total': self.total_targets,
                'message': message,
            })

    def detect_waf(self, headers: dict) -> None:
        combined = f"{headers.get('server', '')} {headers.get('cf-ray', '')} " \
                   f"{headers.get('x-cdn', '')} {headers.get('x-sucuri-id', '')}".lower()
        for vendor, signatures in WAF_SIGNATURES.items():
            if any(sig in combined for sig in signatures):
                self.waf_detected = True
                self.waf_vendor = vendor
                return

    async def discover_and_fingerprint(self, client: httpx.AsyncClient) -> List[Dict[str, Any]]:
        self.emit_log(f"Connecting to {self.target_url} ...")
        try:
            response = await client.get(self.target_url, follow_redirects=True, timeout=10.0)
            response.raise_for_status()
        except httpx.RequestError as exc:
            error_msg = str(exc).lower()
            if 'getaddrinfo' in error_msg or 'name or service not known' in error_msg:
                title = 'Invalid Domain or DNS Error'
                user_msg = ('DNS resolution failed: the domain could not be found. '
                            'Verify the URL spelling and TLD (e.g. .com, .org).')
            elif 'timed out' in error_msg:
                title = 'Connection Timeout'
                user_msg = 'The target did not respond within 10 seconds. It may be offline or blocking your IP.'
            elif 'connection refused' in error_msg:
                title = 'Connection Refused'
                user_msg = 'The target refused the connection. The port may be closed or firewalled.'
            elif 'ssl' in error_msg or 'certificate' in error_msg:
                title = 'SSL Certificate Error'
                user_msg = 'SSL/TLS handshake failed. The certificate may be invalid or self-signed.'
            else:
                title = 'Connection Failed'
                user_msg = f"Network error: {exc}"

            self.emit_log(user_msg, 'error')
            self.results.append({
                'type': 'error', 'title': title, 'description': user_msg,
                'category': 'network', 'cvss': 'N/A', 'severity': 'High',
                'remediation': 'Verify network connectivity and the target URL.',
                'references': [],
            })
            return []

        self.emit_log('Connection successful. Fingerprinting technology stack...', 'success')
        self.detect_waf(dict(response.headers))
        if self.waf_detected:
            self.emit_log(f"WAF detected: {self.waf_vendor}. Encoder strategies will be armed.", 'error')

        techs, cve_findings = fingerprint_target(dict(response.headers), response.text)
        self.tech_stack = techs
        for finding in cve_findings:
            finding['references'] = REFERENCE_LINKS['cve']
        self.results.extend(cve_findings)
        if techs:
            self.emit_log(f"Detected stack: {', '.join(techs)}")
        if cve_findings:
            self.emit_log(f"CRITICAL: {len(cve_findings)} known CVE match(es)!", 'error')

        dom_findings = analyze_dom(response.text)
        for finding in dom_findings:
            finding['url'] = str(response.url)
            finding['method'] = 'CLIENT-SIDE'
        self.results.extend(dom_findings)
        if dom_findings:
            self.emit_log(f"DOM analysis: {len(dom_findings)} potential sink(s) in inline scripts.", 'error')
        else:
            self.emit_log('DOM analysis: no unsafe source-to-sink flows in inline scripts.')

        lowered = {k.lower() for k in response.headers.keys()}
        for header_name, (title, desc, fix) in MISSING_HEADER_RULES.items():
            if header_name not in lowered:
                self.results.append({
                    'type': 'vulnerability',
                    'category': 'missing_header',
                    'title': title,
                    'description': desc,
                    'remediation': fix,
                    'cvss': '3.1 (Low)',
                    'severity': 'Low',
                    'references': REFERENCE_LINKS['missing_header'],
                })

        soup = BeautifulSoup(response.text, 'html.parser')
        targets: List[Dict[str, Any]] = []

        for form in soup.find_all('form'):
            action = form.get('action')
            method = (form.get('method') or 'get').lower()
            if action and not urlparse(action).netloc:
                action = urljoin(str(response.url), action)
            elif not action:
                action = str(response.url)
            params = [i.get('name') for i in form.find_all(['input', 'textarea']) if i.get('name')]
            if params:
                targets.append({'type': 'form', 'url': action, 'method': method, 'params': params})

        parsed = urlparse(str(response.url))
        if parsed.query:
            targets.append({
                'type': 'url_param',
                'url': str(response.url),
                'method': 'get',
                'params': list(parse_qs(parsed.query).keys()),
            })

        self.emit_log(f"Discovered {len(targets)} attack surface(s).", 'success')
        return targets

    def arm_payloads(self) -> None:
        self.active_payloads, meta = build_payload_set(
            mode=self.payload_mode,
            waf_detected=self.waf_detected,
            waf_vendor=self.waf_vendor,
            custom=self.custom_wordlist or None,
        )
        source = 'custom wordlist' if self.custom_wordlist else f"{self.payload_mode} library"
        self.emit_log(
            f"Payload engine armed: {meta['total']} payloads "
            f"({source}, {meta['encoded']} encoded variants).",
            'success',
        )

    async def inject_payload(self, client: httpx.AsyncClient, target: Dict[str, Any],
                             payload: str, attack_type: str) -> Optional[Dict[str, str]]:
        data = {p: payload for p in target['params']}
        try:
            if target['type'] == 'form' and target['method'] == 'post':
                response = await client.post(target['url'], data=data, timeout=10.0)
            else:
                response = await client.get(target['url'], params=data, timeout=10.0)
        except httpx.RequestError:
            return None

        if attack_type == 'xss' and payload in response.text:
            return {'category': 'xss', 'payload': payload}
        if attack_type == 'sqli' and self.sql_error_pattern.search(response.text):
            return {'category': 'sqli', 'payload': payload}
        return None

    async def scan_target(self, client: httpx.AsyncClient, target: Dict[str, Any]) -> None:
        try:
            self.emit_log(f"Probing {target['url']} [{target['type'].upper()}] params={target['params']}")
            tasks = [self.inject_payload(client, target, p, 'xss') for p in self.active_payloads]
            tasks += [self.inject_payload(client, target, p, 'sqli') for p in self.sqli_payloads]

            for result in await asyncio.gather(*tasks):
                if not result:
                    continue
                is_sqli = result['category'] == 'sqli'
                self.emit_log(f"VULNERABILITY: {result['category'].upper()} reflected via {target['params']}", 'error')
                self.results.append({
                    'type': 'vulnerability',
                    'category': result['category'],
                    'title': f"Reflected {result['category'].upper()} Detected",
                    'target_type': target['type'],
                    'url': target['url'],
                    'method': target['method'].upper(),
                    'parameters': target['params'],
                    'payload': result['payload'],
                    'cvss': '8.6 (High)' if is_sqli else '6.1 (Medium)',
                    'remediation': (
                        'Use parameterized queries / prepared statements; never concatenate input into SQL.'
                        if is_sqli else
                        'Apply context-aware output encoding and enable a strict CSP.'
                    ),
                    'severity': 'High' if is_sqli else 'Medium',
                    'references': REFERENCE_LINKS[result['category']],
                })
                break
        finally:
            self.completed_targets += 1
            self.emit_progress(f"Target {self.completed_targets}/{self.total_targets} analyzed")

    async def run_scan(self) -> Dict[str, Any]:
        limits = httpx.Limits(max_connections=20)
        async with httpx.AsyncClient(headers=self.headers, verify=False, limits=limits) as client:
            targets = await self.discover_and_fingerprint(client)
            self.arm_payloads()
            self.total_targets = len(targets)
            self.emit_progress('Attack surfaces discovered')
            if targets:
                await asyncio.gather(*(self.scan_target(client, t) for t in targets))

        duration = round(time.time() - self.start_time, 2)
        vuln_count = len([r for r in self.results if r['type'] == 'vulnerability'])
        self.emit_log(f"Scan completed in {duration}s | findings: {vuln_count}", 'success')
        return {
            'results': self.results,
            'tech_stack': self.tech_stack,
            'duration': duration,
            'waf_detected': self.waf_detected,
            'waf_vendor': self.waf_vendor,
        }