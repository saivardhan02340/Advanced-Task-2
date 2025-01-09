import requests
from urllib.parse import urljoin
from bs4 import BeautifulSoup

class WebAppScanner:
    def __init__(self, base_url):
        self.base_url = base_url
        self.session = requests.Session()

    def find_forms(self, url):
        """Extract all forms from a given URL."""
        response = self.session.get(url)
        soup = BeautifulSoup(response.text, "html.parser")
        return soup.find_all("form")

    def get_form_details(self, form):
        """Extract form details such as action, method, and inputs."""
        action = form.attrs.get("action")
        method = form.attrs.get("method", "get").lower()
        inputs = []
        for input_tag in form.find_all("input"):
            input_name = input_tag.attrs.get("name")
            input_type = input_tag.attrs.get("type", "text")
            input_value = input_tag.attrs.get("value", "")
            inputs.append({"name": input_name, "type": input_type, "value": input_value})
        return {"action": action, "method": method, "inputs": inputs}

    def submit_form(self, form_details, url, payload):
        """Submit a form with a given payload."""
        target_url = urljoin(url, form_details["action"])
        data = {}
        for input in form_details["inputs"]:
            if input["type"] == "text" or input["type"] == "search":
                data[input["name"]] = payload
            else:
                data[input["name"]] = input["value"]

        if form_details["method"] == "post":
            return self.session.post(target_url, data=data)
        else:
            return self.session.get(target_url, params=data)

    def test_xss(self, url):
        """Test for Cross-Site Scripting (XSS) vulnerabilities."""
        forms = self.find_forms(url)
        xss_payload = "<script>alert('XSS')</script>"
        for form in forms:
            form_details = self.get_form_details(form)
            response = self.submit_form(form_details, url, xss_payload)
            if xss_payload in response.text:
                print(f"[+] XSS vulnerability detected on {url}")
                print(f"[*] Form details: {form_details}")

    def test_sql_injection(self, url):
        """Test for SQL Injection vulnerabilities."""
        forms = self.find_forms(url)
        sql_payload = "' OR '1'='1"
        for form in forms:
            form_details = self.get_form_details(form)
            response = self.submit_form(form_details, url, sql_payload)
            if "sql" in response.text.lower() or "syntax" in response.text.lower():
                print(f"[+] SQL Injection vulnerability detected on {url}")
                print(f"[*] Form details: {form_details}")

    def run_scanner(self):
        """Run the scanner to check for vulnerabilities."""
        print(f"Scanning {self.base_url} for vulnerabilities...")
        self.test_xss(self.base_url)
        self.test_sql_injection(self.base_url)

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Web Application Vulnerability Scanner")
    parser.add_argument("url", help="Base URL of the web application to scan")
    args = parser.parse_args()

    scanner = WebAppScanner(args.url)
    scanner.run_scanner()
