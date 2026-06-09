import subprocess
import socket

class DomainCollector:
    def __init__(self, root_domains=None, target_file=None,
                 use_subfinder=True, use_assetfinder=True, use_amass=False):
        self.domains = root_domains or []
        self.target_file = target_file
        self.use_subfinder = use_subfinder
        self.use_assetfinder = use_assetfinder
        self.use_amass = use_amass

    def collect(self):
        all_subdomains = {}
        all_ips = set()
        ip_to_domain = {}

        if self.target_file:
            try:
                with open(self.target_file, "r") as f:
                    self.domains.extend(line.strip() for line in f if line.strip())
            except Exception as e:
                print(f"[!] Error reading target file: {e}")

        for domain in self.domains:
            print(f"[*] Collecting subdomains for {domain}...")
            subdomains = set()

            if self.use_subfinder:
                subdomains.update(self._run_tool("subfinder", domain))
            if self.use_assetfinder:
                subdomains.update(self._run_tool("assetfinder", domain))
            if self.use_amass:
                subdomains.update(self._run_tool("amass", domain))

            if not subdomains:
                print("[!] No subdomains found, using root domain.")
                subdomains.add(domain)

            for sub in subdomains:
                try:
                    ip = socket.gethostbyname(sub)
                    all_ips.add(ip)
                    if ip not in ip_to_domain:
                        ip_to_domain[ip] = sub
                    print(f"    {sub} -> {ip}")
                except socket.gaierror:
                    print(f"    [!] Could not resolve {sub}")

            all_subdomains[domain] = list(subdomains)

        return {
            'subdomains': all_subdomains,
            'ips': list(all_ips),
            'ip_to_domain': ip_to_domain
        }

    def _run_tool(self, tool, domain):
        cmds = {
            "subfinder": ["subfinder", "-d", domain, "-silent"],
            "assetfinder": ["assetfinder", "--subs-only", domain],
            "amass": ["amass", "enum", "-passive", "-d", domain, "-o", "/dev/stdout"]
        }
        cmd = cmds.get(tool)
        if not cmd:
            return []
        print(f"[*] Running: {' '.join(cmd)}")
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            if proc.returncode != 0:
                print(f"[!] {tool} error: {proc.stderr.strip()}")
                return []
            lines = proc.stdout.strip().split('\n')
            return {line.strip() for line in lines if line.strip()}
        except FileNotFoundError:
            print(f"[!] {tool} not found.")
        except Exception as e:
            print(f"[!] {tool} failed: {e}")
        return []
