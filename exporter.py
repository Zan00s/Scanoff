import csv
import json
import os
from datetime import datetime

class Exporter:
    def __init__(self, db_manager, config):
        self.db = db_manager
        self.config = config

    def run_export(self, scan_id=None):
        export_cfg = self.config.export_settings
        if not export_cfg:
            return

        formats = export_cfg.get("formats", ["csv"])
        output_dir = export_cfg.get("output_dir", "workspace/exports")
        os.makedirs(output_dir, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        hosts = self._get_all_hosts()
        technologies = self._get_all_technologies()
        endpoints = self._get_all_endpoints()

        for fmt in formats:
            fmt = fmt.lower().strip()
            if fmt == "csv":
                self._export_csv(hosts, technologies, endpoints, output_dir, timestamp)
            elif fmt == "json":
                self._export_json(hosts, technologies, endpoints, output_dir, timestamp)
            elif fmt == "burp":
                self._export_burp(endpoints, output_dir, timestamp)
            elif fmt == "maltego":
                self._export_maltego(hosts, endpoints, output_dir, timestamp)

    def _get_all_hosts(self):
        conn = self.db._connect()
        cur = conn.cursor()
        cur.execute("SELECT ip, port, service, version, first_seen, last_seen FROM hosts")
        rows = cur.fetchall()
        conn.close()
        return rows

    def _get_all_technologies(self):
        conn = self.db._connect()
        cur = conn.cursor()
        cur.execute("SELECT ip, port, technology, version FROM technologies")
        rows = cur.fetchall()
        conn.close()
        return rows

    def _get_all_endpoints(self):
        conn = self.db._connect()
        cur = conn.cursor()
        cur.execute("SELECT ip, port, url FROM endpoints")
        rows = cur.fetchall()
        conn.close()
        return rows

    def _export_csv(self, hosts, technologies, endpoints, output_dir, timestamp):
        hosts_file = os.path.join(output_dir, f"hosts_{timestamp}.csv")
        with open(hosts_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(["ip", "port", "service", "version", "first_seen", "last_seen"])
            writer.writerows(hosts)

        if technologies:
            tech_file = os.path.join(output_dir, f"technologies_{timestamp}.csv")
            with open(tech_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(["ip", "port", "technology", "version"])
                writer.writerows(technologies)

        if endpoints:
            ep_file = os.path.join(output_dir, f"endpoints_{timestamp}.csv")
            with open(ep_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(["ip", "port", "url"])
                writer.writerows(endpoints)

    def _export_json(self, hosts, technologies, endpoints, output_dir, timestamp):
        data = {
            "hosts": [{"ip": h[0], "port": h[1], "service": h[2], "version": h[3],
                        "first_seen": h[4], "last_seen": h[5]} for h in hosts],
            "technologies": [{"ip": t[0], "port": t[1], "technology": t[2], "version": t[3]} for t in technologies],
            "endpoints": [{"ip": e[0], "port": e[1], "url": e[2]} for e in endpoints]
        }
        json_file = os.path.join(output_dir, f"export_{timestamp}.json")
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)

    def _export_burp(self, endpoints, output_dir, timestamp):
        burp_file = os.path.join(output_dir, f"burp_sitemap_{timestamp}.xml")
        with open(burp_file, 'w', encoding='utf-8') as f:
            f.write('<?xml version="1.0" encoding="UTF-8"?>\n<items>\n')
            for ep in endpoints:
                url = ep[2]
                f.write(f'  <item><url>{url}</url></item>\n')
            f.write('</items>\n')

    def _export_maltego(self, hosts, endpoints, output_dir, timestamp):
        mtg_file = os.path.join(output_dir, f"maltego_{timestamp}.csv")
        with open(mtg_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(["type", "value", "weight"])
            for h in hosts:
                writer.writerow(["IP", h[0], "30"])
            for ep in endpoints:
                writer.writerow(["URL", ep[2], "20"])
