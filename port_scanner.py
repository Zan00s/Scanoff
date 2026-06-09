import subprocess
import json
import socket
import tempfile
import os

class PortScanner:
    def __init__(self, target, ports, rate=300):
        self.target = target
        self.ports = ports
        self.rate = rate

    def scan(self):
        targets = [t.strip() for t in self.target.split(",") if t.strip()]
        
        cmd = ["masscan"]
        
        if len(targets) > 1:
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
                f.write("\n".join(targets))
                temp_path = f.name
            cmd += ["-iL", temp_path]
            print(f"[*] Targets written to temp file: {temp_path}")
        else:
            cmd += ["--range", targets[0]]
        
        cmd += [
            "-p" + self.ports,
            "--rate", str(self.rate),
            "--wait", "0",
            "-oJ", "-"
        ]
        print(f"[*] Running: {' '.join(cmd)}")
        
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True
        )

        for line in proc.stdout:
            line = line.strip()
            if line.startswith("{") and line.endswith("}"):
                try:
                    data = json.loads(line)
                    host = data.get("ip")
                    for port_info in data.get("ports", []):
                        if port_info.get("status") == "open":
                            port = port_info.get("port")
                            yield host, port
                except json.JSONDecodeError:
                    pass
        proc.wait()

        if len(targets) > 1:
            try:
                os.unlink(temp_path)
            except OSError:
                pass

        if proc.returncode != 0:
            raise RuntimeError(f"Masscan failed with code {proc.returncode}")
