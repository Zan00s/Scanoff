import subprocess
import json

GENERIC_TECHS = {"Country", "IP", "Title", "Script", "JQuery", "HTML5", "Email", "UncommonHeaders"}

class TechIdentifier:
    def __init__(self, waf_handler=None):
        self.waf = waf_handler

    def identify(self, url):
        if self.waf:
            self.waf.before_request()
        cmd = ["whatweb", "--no-errors", "-q", "--log-json=-", url]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            if self.waf:
                self.waf.report_response(200 if proc.returncode == 0 else 403)
            if proc.returncode != 0:
                return {}
            for line in proc.stdout.strip().splitlines():
                if line.startswith("{"):
                    data = json.loads(line)
                    plugins = data.get("plugins", {})
                    technologies = {}
                    for name, info in plugins.items():
                        if name in GENERIC_TECHS:
                            continue
                        version = info.get("version", [None])[0]
                        technologies[name] = version if version else ""
                    return technologies
        except Exception:
            if self.waf:
                self.waf.report_response(403)
        return {}
