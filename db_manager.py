import sqlite3
import os
from datetime import datetime

class DatabaseManager:
    def __init__(self, db_path):
        self.db_path = db_path
        self.init_db()

    def _connect(self):
        return sqlite3.connect(self.db_path)

    def init_db(self):
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        
        cur.execute("""
            CREATE TABLE IF NOT EXISTS hosts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL,
                port INTEGER NOT NULL,
                service TEXT,
                version TEXT,
                banner TEXT,
                first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                scan_id INTEGER DEFAULT 0
            )
        """)
        cur.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS idx_host_ip_port
            ON hosts(ip, port)
        """)
        
        cur.execute("""
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                start_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                end_time TIMESTAMP,
                target TEXT
            )
        """)
        
        cur.execute("""
            CREATE TABLE IF NOT EXISTS technologies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL,
                port INTEGER NOT NULL,
                technology TEXT NOT NULL,
                version TEXT,
                first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                scan_id INTEGER DEFAULT 0
            )
        """)
        cur.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS idx_tech_ip_port_tech
            ON technologies(ip, port, technology)
        """)
        
        cur.execute("""
            CREATE TABLE IF NOT EXISTS endpoints (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL,
                port INTEGER NOT NULL,
                url TEXT NOT NULL,
                first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                scan_id INTEGER DEFAULT 0
            )
        """)
        cur.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS idx_endpoint_ip_port_url
            ON endpoints(ip, port, url)
        """)
        
        conn.commit()
        conn.close()

    def start_scan(self, target):
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        now = datetime.now().isoformat()
        cur.execute("INSERT INTO scan_history (start_time, target) VALUES (?, ?)", (now, target))
        conn.commit()
        scan_id = cur.lastrowid
        conn.close()
        return scan_id

    def end_scan(self, scan_id):
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        now = datetime.now().isoformat()
        cur.execute("UPDATE scan_history SET end_time = ? WHERE id = ?", (now, scan_id))
        conn.commit()
        conn.close()

    def get_last_scan_time(self):
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute("SELECT end_time FROM scan_history WHERE end_time IS NOT NULL ORDER BY id DESC LIMIT 1")
        row = cur.fetchone()
        conn.close()
        return row[0] if row else None

    def insert_or_update_host(self, ip, port, service=None, version=None, banner=None, scan_id=0):
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        now = datetime.now().isoformat()
        cur.execute("""
            INSERT INTO hosts (ip, port, service, version, banner, first_seen, last_seen, scan_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(ip, port) DO UPDATE SET
                service = excluded.service,
                version = excluded.version,
                banner = excluded.banner,
                last_seen = excluded.last_seen,
                scan_id = excluded.scan_id
                WHERE service IS NOT excluded.service
                   OR version IS NOT excluded.version
        """, (ip, port, service, version, banner, now, now, scan_id))
        conn.commit()
        conn.close()

    def get_new_host_since(self, previous_scan_time=None):
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        if previous_scan_time is None:
            cur.execute("SELECT ip, port, service, version, first_seen FROM hosts")
        else:
            cur.execute("""
                SELECT ip, port, service, version, first_seen
                FROM hosts
                WHERE first_seen > ?
            """, (previous_scan_time,))
        rows = cur.fetchall()
        conn.close()
        return rows

    def insert_or_update_technology(self, ip, port, technology, version, scan_id=0):
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        now = datetime.now().isoformat()
        cur.execute("""
            INSERT INTO technologies (ip, port, technology, version, first_seen, last_seen, scan_id)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(ip, port, technology) DO UPDATE SET
                version = excluded.version,
                last_seen = excluded.last_seen,
                scan_id = excluded.scan_id
        """, (ip, port, technology, version, now, now, scan_id))
        conn.commit()
        conn.close()

    def insert_or_update_endpoint(self, ip, port, url, scan_id=0):
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        now = datetime.now().isoformat()
        cur.execute("""
            INSERT INTO endpoints (ip, port, url, first_seen, last_seen, scan_id)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(ip, port, url) DO UPDATE SET
                last_seen = excluded.last_seen,
                scan_id = excluded.scan_id
        """, (ip, port, url, now, now, scan_id))
        conn.commit()
        conn.close()
