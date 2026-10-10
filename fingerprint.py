import re
from typing import Any, Dict, List, Tuple

TECH_SIGNATURES = {
    'Apache': re.compile(r'Apache/?([0-9.]+)?', re.I),
    'Nginx': re.compile(r'nginx/?([0-9.]+)?', re.I),
    'PHP': re.compile(r'PHP/?([0-9.]+)?', re.I),
    'ASP.NET': re.compile(r'ASP\.NET', re.I),
    'Cloudflare': re.compile(r'cloudflare', re.I),
    'WordPress': re.compile(r'wp-content|wordpress', re.I),
}

KNOWN_CVES = {
    'Apache 2.4.49': {'cve': 'CVE-2021-41773', 'desc': 'Path Traversal & RCE', 'severity': 'Critical'},
    'Apache 2.4.50': {'cve': 'CVE-2021-42013', 'desc': 'Path Traversal Bypass', 'severity': 'Critical'},
    'PHP 7.4': {'cve': 'CVE-2021-21703', 'desc': 'Use after free in SOAP', 'severity': 'High'},
}


def fingerprint_target(headers: dict, html_body: str) -> Tuple[List[str], List[Dict[str, Any]]]:
    detected_tech: List[str] = []
    vulnerabilities: List[Dict[str, Any]] = []
    combined_headers = f"{headers.get('server', '')} {headers.get('x-powered-by', '')}"

    for tech, regex in TECH_SIGNATURES.items():
        if tech == 'WordPress':
            continue
        match = regex.search(combined_headers)
        if match:
            version = match.group(1) if match.group(1) else 'Unknown'
            tech_str = f"{tech} {version}".strip()
            detected_tech.append(tech_str)
            if tech_str in KNOWN_CVES:
                info = KNOWN_CVES[tech_str]
                vulnerabilities.append({
                    'type': 'vulnerability',
                    'category': 'cve',
                    'title': f"Known CVE in {tech_str}",
                    'description': f"{info['desc']} ({info['cve']})",
                    'cvss': '9.8 (Critical)',
                    'remediation': f"Upgrade {tech} to the latest patched version immediately.",
                    'severity': info['severity'],
                })

    if TECH_SIGNATURES['WordPress'].search(html_body):
        detected_tech.append('WordPress')

    return list(set(detected_tech)), vulnerabilities