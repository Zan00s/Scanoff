import subprocess
import os

class Screenshotter:
    def __init__(self, output_dir="workspace/screenshots", timeout=30):
        self.output_dir = output_dir
        self.timeout = timeout

    def take_screenshots(self, urls):
        if not urls:
            return
        os.makedirs(self.output_dir, exist_ok=True)
        cmd = [
            "gowitness", "scan", "file", "-f", "/dev/stdin",
            "--screenshot-path", self.output_dir,
            "--timeout", str(self.timeout)
        ]
        proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, text=True)
        proc.communicate(input="\n".join(urls))
        proc.wait()
        print(f"[*] Screenshots saved to {self.output_dir}")
