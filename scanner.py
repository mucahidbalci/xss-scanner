import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import random
import string


class XSSScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) SecureAuditBot/1.0'
        })

        # Harmless, standard XSS payloads for detection
        self.payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "\"><svg/onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<body onload=alert('XSS')>"
        ]

        self.results = []

    def _generate_random_string(self, length=8):
        return ''.join(random.choices(string.ascii_lowercase, k=length))

    def discover_forms(self):
        """Fetches the target URL and extracts all HTML forms."""
        try:
            response = self.session.get(self.target_url, timeout=10)
            response.raise_for_status()
        except requests.exceptions.RequestException as e:
            return [], f"Failed to connect to target: {str(e)}"

        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')

        parsed_forms = []
        for form in forms:
            action = form.get('action')
            method = form.get('method', 'get').lower()

            # Resolve relative URLs
            if action and not urlparse(action).netloc:
                action = urljoin(self.target_url, action)
            elif not action:
                action = self.target_url

            inputs = []
            for input_tag in form.find_all(['input', 'textarea', 'select']):
                input_name = input_tag.get('name')
                input_type = input_tag.get('type', 'text')
                if input_name:
                    inputs.append({'name': input_name, 'type': input_type})

            if inputs:
                parsed_forms.append({
                    'action': action,
                    'method': method,
                    'inputs': inputs
                })

        return parsed_forms, None

    def test_payload(self, form_data, payload):
        """Tests a specific payload against a form and checks for reflection."""
        action = form_data['action']
        method = form_data['method']

        # Fill all inputs with the payload
        data = {}
        for inp in form_data['inputs']:
            data[inp['name']] = payload

        try:
            if method == 'post':
                response = self.session.post(action, data=data, timeout=10)
            else:
                response = self.session.get(action, params=data, timeout=10)

            # Check if the payload is reflected in the response without being encoded
            if payload in response.text:
                return True, response.text
            return False, None

        except requests.exceptions.RequestException:
            return False, None

    def scan(self):
        """Main execution method. Returns a list of vulnerabilities found."""
        forms, error = self.discover_forms()

        if error:
            return [{'type': 'error', 'message': error}]

        if not forms:
            return [{'type': 'info', 'message': 'No forms found on the target page.'}]

        for form in forms:
            for payload in self.payloads:
                is_vulnerable, response_text = self.test_payload(form, payload)

                if is_vulnerable:
                    self.results.append({
                        'type': 'vulnerability',
                        'url': form['action'],
                        'method': form['method'].upper(),
                        'payload': payload,
                        'inputs': [inp['name'] for inp in form['inputs']],
                        'status': 'Reflected (Potential XSS)'
                    })
                    # Stop testing other payloads for this form if one works
                    break

        if not self.results:
            self.results.append({'type': 'info', 'message': 'Scan complete. No XSS vulnerabilities detected.'})

        return self.results