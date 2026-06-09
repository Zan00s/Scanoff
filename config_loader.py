import yaml
import os

class Config:
    def __init__(self, path="config.yaml"):
        self.path = path
        if not os.path.exists(path):
            self.data = {}
        else:
            with open(path, "r", encoding="utf-8") as f:
                self.data = yaml.safe_load(f) or {}

    @property
    def masscan_ports(self):
        return self.data.get("masscan", {}).get("ports", "80,443,22")

    @property
    def masscan_rate(self):
        return self.data.get("masscan", {}).get("rate", 100)

    @property
    def masscan_target(self):
        return self.data.get("masscan", {}).get("target", "")

    @property
    def db_path(self):
        return self.data.get("database", {}).get("path", "workspace/scan.db")

    @property
    def tg_bot_token(self):
        return self.data.get("telegram", {}).get("bot_token", "")

    @property
    def tg_chat_id(self):
        return self.data.get("telegram", {}).get("chat_id", "")

    @property
    def telegram_proxy(self):
        return self.data.get("telegram", {}).get("proxy", "")

    @property
    def osint_root_domains(self):
        return self.data.get("osint", {}).get("root_domains", [])

    @property
    def osint_use_subfinder(self):
        return self.data.get("osint", {}).get("use_subfinder", True)

    @property
    def osint_use_assetfinder(self):
        return self.data.get("osint", {}).get("use_assetfinder", True)

    @property
    def osint_use_amass(self):
        return self.data.get("osint", {}).get("use_amass", False)

    @property
    def export_settings(self):
        return self.data.get("export", {})

    @property
    def schedule_interval(self):
        return self.data.get("schedule", {}).get("interval", 0)

    @property
    def screenshot_enabled(self):
        return self.data.get("screenshots", {}).get("enabled", False)

    @property
    def screenshot_output_dir(self):
        return self.data.get("screenshots", {}).get("output_dir", "workspace/screenshots")

    @property
    def nuclei_enabled(self):
        return self.data.get("nuclei", {}).get("enabled", False)

    @property
    def swagger_enabled(self):
        return self.data.get("swagger", {}).get("enabled", False)

    @property
    def dashboard_enabled(self):
        return self.data.get("dashboard", {}).get("enabled", False)

    @property
    def dashboard_host(self):
        return self.data.get("dashboard", {}).get("host", "127.0.0.1")

    @property
    def dashboard_port(self):
        return self.data.get("dashboard", {}).get("port", 5000)

    @property
    def target_file(self):
        return self.data.get("target_file", None)

    def save(self, data):
        self.data = data
        with open(self.path, "w", encoding="utf-8") as f:
            yaml.dump(self.data, f)
