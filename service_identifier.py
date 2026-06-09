import socket
import re

class ServiceIdentifier:
    SIGNATURES = [
        (re.compile(rb'SSH-([\d.]+)'), 'ssh', 1),
        (re.compile(rb'([\d.]+)[-a-zA-Z0-9_]*\x00'), 'mysql', 1),
        (re.compile(rb'"version"\s*:\s*\{\s*"number"\s*:\s*"([^"]+)"'), 'elasticsearch', 1),
        (re.compile(rb'(?i)HTTP/[\d.]+\s+\d{3}'), 'http', None),
        (re.compile(rb'Server:\s*([^\r\n]+)'), 'http-server-header', 1),
        (re.compile(rb'Content-Type:\s*([^\r\n]+)'), 'http-content-type', 1),
        (re.compile(rb'220[ -].*?FTP'), 'ftp', None),
        (re.compile(rb'Remote desktop|RDP|Protocol Error'), 'rdp-or-tls', None),
        (re.compile(rb'220[ -](.*?)\s+ESMTP'), 'smtp', 1),
        (re.compile(rb'220[ -](.*?)FTP'), 'ftp', 1),
        (re.compile(rb'\+OK\s+(.*)'), 'pop3', 1),
        (re.compile(rb'\*\s+OK\s+(.*)'), 'imap', 1),
        (re.compile(rb'\+PONG'), 'redis', None),
        (re.compile(rb'FATAL:'), 'postgresql', None),
        (re.compile(rb'RFB\s+([\d.]+)'), 'vnc', 1),
    ]

    ACTIVE_PROBES = {
        80:   [b'GET / HTTP/1.0\r\n\r\n', b'GET / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\nConnection: close\r\n\r\n'],
        443:  [b'GET / HTTP/1.0\r\n\r\n'],
        8080: [b'GET / HTTP/1.0\r\n\r\n', b'GET / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\nConnection: close\r\n\r\n'],
        9200: [b'GET / HTTP/1.0\r\nHost: localhost\r\n\r\n'],
        5601: [b'GET / HTTP/1.0\r\nHost: localhost\r\n\r\n'],
        6379: [b'PING\r\n'],
        5432: [b'\x00\x00\x00\x00'],
    }

    def __init__(self, timeout=2.0):
        self.timeout = timeout

    def grab_banner(self, ip, port):
        try:
            with socket.create_connection((ip, port), timeout=self.timeout) as sock:
                sock.settimeout(0.5)
                try:
                    data = sock.recv(4096)
                    if data:
                        return data
                except socket.timeout:
                    pass

                probes = self._get_probes(port)
                if not probes:
                    return None

                for probe in probes:
                    sock.settimeout(self.timeout)
                    sock.sendall(probe)
                    response = b''
                    try:
                        while True:
                            chunk = sock.recv(1024)
                            if not chunk:
                                break
                            response += chunk
                    except socket.timeout:
                        pass
                    if response:
                        return response
                return None
        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            print(f"[!] Banner failed for {ip}:{port} - {e}")
            return None

    def _get_probes(self, port):
        if port in self.ACTIVE_PROBES:
            return self.ACTIVE_PROBES[port]
        if port in [8000, 8443, 9000, 9090] or (8000 <= port <= 8999):
            return [b'GET / HTTP/1.0\r\n\r\n']
        return None

    def identify(self, banner: bytes):
        if not banner:
            return "unknown", None
        for pattern, service, version_group in self.SIGNATURES:
            match = pattern.search(banner)
            if match:
                version = match.group(version_group).decode(errors='ignore') if version_group else None
                return service, version
        if b'{' in banner and b'}' in banner:
            return "json_api", None
        return "unknown", None
