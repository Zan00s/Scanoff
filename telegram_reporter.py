import sqlite3
import re
import requests

class TelegramReporter:
    def __init__(self, db_path, bot_token, chat_id, proxy=None):
        self.db_path = db_path
        self.token = bot_token
        self.chat_id = chat_id
        self.proxy = {"https": proxy} if proxy else None

    @staticmethod
    def _escape_mdv2(text):
        if text is None:
            return ""
        escape_chars = r'_*[]()~`>#+-=|{}.!'
        return re.sub(f'([{re.escape(escape_chars)}])', r'\\\1', str(text))

    def generate_and_send(self, scan_id=None):
        if not self.token or not self.chat_id:
            return

        hosts = self._fetch_hosts(scan_id)
        technologies = self._fetch_technologies(scan_id)
        endpoints = self._fetch_endpoints(scan_id)

        if not hosts and not technologies and not endpoints:
            return

        md = "🔍 *Recon\\-Workbench Report*\n\n"

        if hosts:
            md += "*Open Ports & Services:*\n"
            for ip, port, service, version in hosts:
                line = f"• `{self._escape_mdv2(ip)}:{port}` — {self._escape_mdv2(service)}"
                if version:
                    line += f" \\({self._escape_mdv2(version)}\\)"
                md += line + "\n"

        if technologies:
            md += "\n*Technologies:*\n"
            for ip, port, tech, ver in technologies:
                line = f"• `{self._escape_mdv2(ip)}:{port}` {self._escape_mdv2(tech)}"
                if ver:
                    line += f" \\({self._escape_mdv2(ver)}\\)"
                md += line + "\n"

        if endpoints:
            preview = endpoints[:20]
            md += "\n*Endpoints \\(first 20\\):*\n"
            for ip, port, url in preview:
                md += f"• `{self._escape_mdv2(url)}`\n"

        url = f"https://api.telegram.org/bot{self.token}/sendMessage"
        payload = {
            "chat_id": self.chat_id,
            "text": md,
            "parse_mode": "MarkdownV2",
            "disable_web_page_preview": True
        }
        try:
            resp = requests.post(url, json=payload, timeout=10, proxies=self.proxy)
            if resp.status_code != 200:
                print(f"[!] Telegram error: {resp.text}")
        except Exception as e:
            print(f"[!] Telegram request failed: {e}")

    def _fetch_hosts(self, scan_id):
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        if scan_id:
            cur.execute("SELECT ip, port, service, version FROM hosts WHERE scan_id=?", (scan_id,))
        else:
            cur.execute("SELECT ip, port, service, version FROM hosts ORDER BY last_seen DESC LIMIT 50")
        rows = cur.fetchall()
        conn.close()
        return rows

    def _fetch_technologies(self, scan_id):
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        if scan_id:
            cur.execute("SELECT ip, port, technology, version FROM technologies WHERE scan_id=?", (scan_id,))
        else:
            cur.execute("SELECT ip, port, technology, version FROM technologies ORDER BY last_seen DESC LIMIT 50")
        rows = cur.fetchall()
        conn.close()
        return rows

    def _fetch_endpoints(self, scan_id):
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        if scan_id:
            cur.execute("SELECT ip, port, url FROM endpoints WHERE scan_id=?", (scan_id,))
        else:
            cur.execute("SELECT ip, port, url FROM endpoints ORDER BY last_seen DESC LIMIT 100")
        rows = cur.fetchall()
        conn.close()
        return rows
