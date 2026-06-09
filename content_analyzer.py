import subprocess
import requests
import os
from urllib.parse import urljoin

class ContentAnalyzer:
    def __init__(self, wordlist=None, waf_handler=None):
        self.wordlist = wordlist or "/usr/share/wordlists/dirb/common.txt"
        self.waf = waf_handler

    def analyze(self, base_url):
        findings = {
            "robots": None,
            "sitemap": None,
            "directories": [],
            "endpoints": []
        }

        # robots.txt
        robots_url = urljoin(base_url, "/robots.txt")
        try:
            if self.waf:
                self.waf.before_request()
            r = requests.get(robots_url, timeout=5, allow_redirects=False)
            if self.waf:
                self.waf.report_response(r.status_code)
            if r.status_code == 200:
                findings["robots"] = r.text
                print(f"      [robots.txt] found ({len(r.text)} bytes)")
        except Exception:
            if self.waf:
                self.waf.report_response(403)

        # sitemap.xml
        sitemap_url = urljoin(base_url, "/sitemap.xml")
        try:
            if self.waf:
                self.waf.before_request()
            r = requests.get(sitemap_url, timeout=5, allow_redirects=False)
            if self.waf:
                self.waf.report_response(r.status_code)
            if r.status_code == 200:
                findings["sitemap"] = r.text
                print(f"      [sitemap.xml] found ({len(r.text)} bytes)")
        except Exception:
            if self.waf:
                self.waf.report_response(403)

        if self.wordlist:
            findings["directories"] = self._fuzz_directories(base_url)

        findings["endpoints"] = self._crawl_endpoints(base_url)

        return findings

    def _fuzz_directories(self, base_url):
        cmd = [
            "ffuf", "-u", f"{base_url}/FUZZ",
            "-w", self.wordlist,
            "-mc", "200,301,302,403",
            "-s",
            "-t", "20",
            "-timeout", "3",
            "-k"
        ]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            if self.waf:
                self.waf.report_response(200 if proc.returncode == 0 else 403)
            if proc.returncode == 0:
                dirs = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
                for d in dirs:
                    print(f"      [dir] {d}")
                return dirs
        except subprocess.TimeoutExpired:
            if self.waf:
                self.waf.report_response(403)
            print("      [!] ffuf timeout")
        except Exception as e:
            if self.waf:
                self.waf.report_response(403)
            print(f"      [!] ffuf error: {e}")
        return []

    def _crawl_endpoints(self, base_url):
        possible_paths = [
            "/home/kali/go/bin/katana",
            "/usr/local/bin/katana",
            "katana"
        ]
        katana_bin = None
        for path in possible_paths:
            if os.path.exists(path) or path == "katana":
                katana_bin = path
                break

        if katana_bin is None:
            print("      [!] katana not found, skipping crawling")
            return []

        cmd = [katana_bin, "-u", base_url, "-silent", "-d", "2"]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if self.waf:
                self.waf.report_response(200 if proc.returncode == 0 else 403)
            if proc.returncode == 0:
                endpoints = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
                for ep in endpoints:
                    print(f"      [endpoint] {ep}")
                return endpoints
        except FileNotFoundError:
            print("      [!] katana not installed, skipping crawling")
        except Exception as e:
            if self.waf:
                self.waf.report_response(403)
            print(f"      [!] katana error: {e}")
        return []
