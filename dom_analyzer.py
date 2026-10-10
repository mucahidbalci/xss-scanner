import re
from typing import Any, Dict, List, Tuple

from bs4 import BeautifulSoup

SOURCE_PATTERN = re.compile(
    r"location\s*\.\s*(?:hash|search|href|pathname|host|hostname|origin)"
    r"|document\s*\.\s*(?:URL|documentURI|referrer|cookie)"
    r"|document\s*\.\s*location"
    r"|window\s*\.\s*name"
    r"|URLSearchParams"
    r"|event\s*\.\s*data"
    r"|\blocation\s*\["
)

SINKS: List[Tuple[str, re.Pattern, str]] = [
    ('innerHTML', re.compile(r"\.innerHTML\s*="), 'Medium'),
    ('outerHTML', re.compile(r"\.outerHTML\s*="), 'Medium'),
    ('document.write', re.compile(r"document\s*\.\s*write\s*\("), 'Medium'),
    ('document.writeln', re.compile(r"document\s*\.\s*writeln\s*\("), 'Medium'),
    ('eval', re.compile(r"[^.\w]eval\s*\("), 'High'),
    ('Function constructor', re.compile(r"[^.\w]Function\s*\(\s*['\"`]"), 'High'),
    ('setTimeout string arg', re.compile(r"setTimeout\s*\(\s*['\"`]"), 'High'),
    ('setInterval string arg', re.compile(r"setInterval\s*\(\s*['\"`]"), 'High'),
    ('insertAdjacentHTML', re.compile(r"\.insertAdjacentHTML\s*\("), 'Medium'),
    ('jQuery.html', re.compile(r"\$\s*\([^)]*\)\s*\.\s*html\s*\("), 'Medium'),
    ('jQuery DOM insert', re.compile(r"\$\s*\([^)]*\)\s*\.\s*(?:append|prepend|after|before)\s*\("), 'Medium'),
    ('srcdoc', re.compile(r"\.srcdoc\s*="), 'Medium'),
    ('location redirect', re.compile(r"location\s*(?:\.\s*href)?\s*=\s*|location\s*\.\s*(?:assign|replace)\s*\("), 'Medium'),
]

ASSIGN_PATTERN = re.compile(r"(?:var|let|const)?\s*([A-Za-z_$][\w$]{0,30})\s*=(?!=)")

REMEDIATION = (
    'Replace innerHTML/document.write with textContent or safe DOM APIs. '
    'Sanitize untrusted input with DOMPurify before insertion. '
    'Never pass URL-derived values into eval, Function or timer callbacks.'
)

REFERENCES = [
    'https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html',
    'https://portswigger.net/web-security/cross-site-scripting/dom-based',
]


def analyze_dom(html: str) -> List[Dict[str, Any]]:
    soup = BeautifulSoup(html, 'html.parser')
    findings: List[Dict[str, Any]] = []
    seen = set()

    for idx, script in enumerate(soup.find_all('script'), start=1):
        code = script.string or script.get_text() or ''
        if not code.strip():
            continue
        lines = code.splitlines()

        tainted = set()
        for line in lines:
            src_match = SOURCE_PATTERN.search(line)
            if not src_match:
                continue
            for assign in ASSIGN_PATTERN.finditer(line):
                if assign.start() < src_match.start():
                    tainted.add(assign.group(1))

        for line_no, line in enumerate(lines, start=1):
            src_match = SOURCE_PATTERN.search(line)
            for sink_name, sink_pattern, severity in SINKS:
                if not sink_pattern.search(line):
                    continue

                source_label = None
                if src_match:
                    source_label = src_match.group(0)
                else:
                    for var in tainted:
                        if re.search(r"\b" + re.escape(var) + r"\b", line):
                            source_label = f"tainted variable '{var}'"
                            break
                if not source_label:
                    continue

                snippet = line.strip()[:140]
                key = (sink_name, snippet)
                if key in seen:
                    continue
                seen.add(key)

                findings.append({
                    'type': 'vulnerability',
                    'category': 'dom_xss',
                    'title': f"Potential DOM-Based XSS via {sink_name}",
                    'description': (
                        f"Untrusted source '{source_label}' reaches dangerous sink '{sink_name}' "
                        f"in inline script #{idx}, line {line_no}. Execution happens client-side, "
                        f"so server-side reflection checks cannot detect this class."
                    ),
                    'severity': severity,
                    'cvss': '7.3 (High)' if severity == 'High' else '6.1 (Medium)',
                    'remediation': REMEDIATION,
                    'payload': snippet,
                    'references': REFERENCES,
                })

    return findings