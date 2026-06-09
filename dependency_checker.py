# Copyright (c) 2026 Zan00s
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

import subprocess
import shutil
import sys
import os

REQUIRED_TOOLS = {
    "masscan": "sudo apt install --reinstall -y masscan",
    "whatweb": "sudo apt install -y whatweb",
    "ffuf": "go install github.com/ffuf/ffuf/v2@latest",
    "katana": "go install github.com/projectdiscovery/katana/cmd/katana@latest",
    "subfinder": "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    "assetfinder": "go install github.com/tomnomnom/assetfinder@latest",
    "gowitness": "go install github.com/sensepost/gowitness@latest",
    "nuclei": "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
}

def _search_in_system(tool):
    if shutil.which(tool):
        return True
    for path in ["/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin"]:
        if os.path.isfile(os.path.join(path, tool)):
            return True
    return False

def _find_with_dpkg(tool):
    try:
        proc = subprocess.run(["dpkg", "-L", tool], capture_output=True, text=True)
        if proc.returncode == 0:
            for line in proc.stdout.splitlines():
                if line.endswith(tool) and os.path.isfile(line):
                    return os.path.dirname(line)
    except Exception:
        pass
    return None

def _ensure_in_path(tool, path):
    link_dir = "/usr/local/bin"
    link_path = os.path.join(link_dir, tool)
    if os.path.isfile(link_path):
        return
    try:
        os.symlink(os.path.join(path, tool), link_path)
        print(f"[*] Created symlink {link_path} -> {os.path.join(path, tool)}")
    except Exception as e:
        print(f"[!] Could not create symlink: {e}")

def _set_capabilities_if_needed(tool):
    if not _search_in_system(tool):
        return
    tool_path = shutil.which(tool)
    if not tool_path:
        for path in ["/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin"]:
            candidate = os.path.join(path, tool)
            if os.path.isfile(candidate):
                tool_path = candidate
                break
    if not tool_path:
        return
    try:
        subprocess.run(f"sudo setcap cap_net_raw,cap_net_admin+eip {tool_path}", shell=True, check=True)
        print(f"  [*] Capabilities set for {tool_path}")
    except subprocess.CalledProcessError:
        print(f"  [!] Could not set capabilities for {tool_path}. Run manually:")
        print(f"      sudo setcap cap_net_raw,cap_net_admin+eip {tool_path}")

def check_dependencies():
    missing = []
    for tool, install_cmd in REQUIRED_TOOLS.items():
        if _search_in_system(tool):
            continue
        found_path = _find_with_dpkg(tool)
        if found_path:
            _ensure_in_path(tool, found_path)
            if _search_in_system(tool):
                continue
        missing.append((tool, install_cmd))
    return missing

def show_banner():
    banner = r"""
 ______  _______  _______  _______  _______  _______  _______ 
/ _____)(_______)(_______)(_______)(_______)(_______)(_______)
( (____   _        _______  _     _  _     _  _____    _____   
 \____ \ | |      |  ___  || |   | || |   | ||  ___)  |  ___)  
 _____) )| |_____ | |   | || |   | || |___| || |      | |      
(______/  \______)|_|   |_||_|   |_| \_____/ |_|      |_|      
                                                               
              SCANOFF v1.0 - by Zan00s
    """
    print(banner)

def auto_install(missing):
    print("\n[*] Installing missing tools...\n")
    for tool, cmd in missing:
        print(f"  -> {tool}")
        try:
            subprocess.run(cmd, shell=True, check=True)
        except subprocess.CalledProcessError:
            print(f"  [!] Failed to install {tool}. Try manually: {cmd}")
        if tool == "masscan":
            _set_capabilities_if_needed("masscan")
    print("\n[*] Installation finished.\n")

def check_and_install_dependencies():
    missing = check_dependencies()
    if not missing:
        print("[*] All required tools are installed.\n")
        _set_capabilities_if_needed("masscan")
        return

    print("[!] Some required tools are missing:")
    for tool, _ in missing:
        print(f"    - {tool}")
    answer = input("\nDo you want to install them automatically? (y/n): ").strip().lower()
    if answer == 'y':
        auto_install(missing)
        still_missing = check_dependencies()
        if still_missing:
            print("[!] These tools are still missing:")
            for tool, cmd in still_missing:
                print(f"    - {tool}  | manual install: {cmd}")
            sys.exit(1)
        else:
            print("[*] All tools are now installed.\n")
    else:
        print("[!] Cannot continue without required tools. Exiting.")
        sys.exit(1)
