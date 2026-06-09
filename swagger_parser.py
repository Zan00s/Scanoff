import requests
import json
from urllib.parse import urljoin

class SwaggerParser:
    def parse(self, base_url):
        endpoints = []
        endpoints.extend(self._try_swagger_json(base_url))
        if not endpoints:
            endpoints.extend(self._try_swagger_ui(base_url))
        return endpoints

    def _try_swagger_json(self, base_url):
        for path in ["/swagger.json", "/v2/api-docs", "/v3/api-docs", "/openapi.json"]:
            url = urljoin(base_url, path)
            try:
                r = requests.get(url, timeout=5)
                if r.status_code == 200 and r.headers.get("content-type","").startswith("application/json"):
                    spec = r.json()
                    return self._extract_endpoints(spec, base_url)
            except Exception:
                continue
        return []

    def _try_swagger_ui(self, base_url):
        try:
            r = requests.get(urljoin(base_url, "/swagger-ui.html"), timeout=5)
            if r.status_code == 200:
                return [base_url + "/swagger-ui.html"]
        except Exception:
            pass
        return []

    def _extract_endpoints(self, spec, base_url):
        paths = spec.get("paths", {})
        result = []
        for path, methods in paths.items():
            full_url = urljoin(base_url, path)
            result.append(full_url)
        return result
