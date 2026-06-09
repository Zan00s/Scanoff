#!/usr/bin/env python3
# Copyright (c) 2026 Zan00s
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

import argparse
import sys
import os
import ipaddress
from dependency_checker import check_and_install_dependencies, show_banner
from config_loader import Config
from db_manager import DatabaseManager
from port_scanner import PortScanner
from service_identifier import ServiceIdentifier
from notifier import TelegramNotifier
from domain_collector import DomainCollector
from tech_identifier import TechIdentifier
from content_analyzer import ContentAnalyzer
from waf_handler import WafHandler
from exporter import Exporter
from telegram_reporter import TelegramReporter
from screenshotter import Screenshotter
from vuln_scanner import VulnScanner
from swagger_parser import SwaggerParser
from concurrent.futures import ThreadPoolExecutor, as_completed

AUTHOR = "Zan00s"
LICENSE = "AGPL-3.0 License - Copyright (c) 2026 " + AUTHOR

def process_port(ip, port, service_identifier):
    banner = service_identifier.grab_banner(ip, port)
    service, version = service_identifier.identify(banner)
    return ip, port, service, version, banner

def analyze_http(ip, port, url, db, tech_identifier, content_analyzer, current_scan_id):
    techs = tech_identifier.identify(url)
    for tech, ver in techs.items():
        db.insert_or_update_technology(ip, port, tech, ver, current_scan_id)
        print(f"      {ip}:{port} Tech: {tech} {ver}")

    findings = content_analyzer.analyze(url)
    for ep in findings.get("endpoints", []):
        db.insert_or_update_endpoint(ip, port, ep, current_scan_id)

def parse_targets(targets):
    domains = []
    ips = []
    for t in targets:
        t = t.strip()
        if not t:
            continue
        try:
            ipaddress.ip_network(t, strict=False)
            ips.append(t)
        except ValueError:
            domains.append(t)
    return domains, ips

def run_full_scan(config, db, waf, tech_identifier, content_analyzer, masscan_target=None, ports=None, rate=None):
    all_ips = set()
    ip_to_domain = {}

    raw_targets = []
    if masscan_target:
        raw_targets.extend([x.strip() for x in masscan_target.split(",") if x.strip()])
    if config.target_file:
        try:
            with open(config.target_file, "r") as f:
                raw_targets.extend(line.strip() for line in f if line.strip())
        except Exception as e:
            print(f"[!] Error reading target file: {e}")
    if config.osint_root_domains:
        raw_targets.extend(config.osint_root_domains)

    domains, explicit_ips = parse_targets(raw_targets)
    all_ips.update(explicit_ips)

    if domains:
        print("[*] Starting OSINT collection...")
        collector = DomainCollector(
            root_domains=domains,
            use_subfinder=config.osint_use_subfinder,
            use_assetfinder=config.osint_use_assetfinder,
            use_amass=config.osint_use_amass
        )
        osint_data = collector.collect()
        all_ips.update(osint_data['ips'])
        ip_to_domain.update(osint_data.get('ip_to_domain', {}))

    if not all_ips:
        print("[-] No targets to scan.")
        return

    ip_list = list(all_ips)
    _ports = ports if ports else config.masscan_ports
    _rate = rate if rate else config.masscan_rate

    masscan_target_str = ",".join(ip_list)
    last_time = db.get_last_scan_time()
    current_scan_id = db.start_scan(masscan_target_str)

    scanner = PortScanner(masscan_target_str, _ports, _rate)
    service_identifier = ServiceIdentifier()

    open_ports = []
    try:
        for ip, port in scanner.scan():
            print(f"[+] Open port: {ip}:{port}")
            open_ports.append((ip, port))
    except Exception as e:
        print(f"Scan aborted during masscan: {e}")
        db.end_scan(current_scan_id)
        return

    banner_executor = ThreadPoolExecutor(max_workers=20)
    http_executor = ThreadPoolExecutor(max_workers=10)

    banner_futures = []
    for ip, port in open_ports:
        future = banner_executor.submit(process_port, ip, port, service_identifier)
        banner_futures.append((future, ip, port))

    http_futures = []
    http_urls = []

    for future, ip, port in banner_futures:
        try:
            ip, port, service, version, banner = future.result()
            if service == 'unknown' and port in (80, 443, 8080, 8443):
                service = 'http'
            print(f"    {ip}:{port} Service: {service}, version: {version}")
            db.insert_or_update_host(ip, port, service, version, banner, current_scan_id)

            if service in ('http', 'http-server-header', 'http-content-type', 'json_api') or port in (80, 443, 8080, 8443):
                host = ip_to_domain.get(ip, ip)
                url = f"http://{host}:{port}" if port != 443 else f"https://{host}:{port}"
                http_urls.append(url)
                http_future = http_executor.submit(analyze_http, ip, port, url, db, tech_identifier, content_analyzer, current_scan_id)
                http_futures.append(http_future)
        except Exception as e:
            print(f"    [!] Error processing {ip}:{port} - {e}")

    for future in as_completed(http_futures):
        try:
            future.result()
        except Exception as e:
            print(f"    [!] HTTP analysis error: {e}")

    banner_executor.shutdown(wait=True)
    http_executor.shutdown(wait=True)

    if config.screenshot_enabled and http_urls:
        print("[*] Taking screenshots...")
        screenshotter = Screenshotter(output_dir=config.screenshot_output_dir)
        screenshotter.take_screenshots(http_urls)

    if config.nuclei_enabled and http_urls:
        print("[*] Running Nuclei...")
        vuln_scanner = VulnScanner()
        vulns = vuln_scanner.scan(http_urls)
        for v in vulns:
            print(f"    [!] {v.get('info', {}).get('name')} [{v.get('severity')}] confidence: {v.get('confidence')}")

    if config.swagger_enabled and http_urls:
        print("[*] Parsing Swagger...")
        swagger_parser = SwaggerParser()
        for url in http_urls:
            swagger_endpoints = swagger_parser.parse(url)
            for ep in swagger_endpoints:
                print(f"      [swagger] {ep}")

    db.end_scan(current_scan_id)

    new_hosts = db.get_new_host_since(last_time)

    if new_hosts:
        message_lines = ["New ports/services found:"]
        for ip, port, svc, ver, _ in new_hosts:
            message_lines.append(f"  {ip}:{port} - {svc} {ver or ''}")
        message = "\n".join(message_lines)
        token = config.tg_bot_token
        chat_id = config.tg_chat_id
        if token and chat_id:
            notifier = TelegramNotifier(token, chat_id)
            notifier.send_message(message)
            print("Notification sent.")

    reporter = TelegramReporter(config.db_path, config.tg_bot_token, config.tg_chat_id)
    reporter.generate_and_send(current_scan_id)

    exporter = Exporter(db, config)
    exporter.run_export(current_scan_id)

def interactive_config(existing_config=None):
    print("\nScanoff - Configuration Setup\n")
    data = {}

    print(">> Masscan Settings")
    data["masscan"] = {}
    default_ports = existing_config.masscan_ports if existing_config else "80,443,22"
    data["masscan"]["ports"] = input(f"  Ports to scan (default {default_ports}): ") or default_ports
    default_rate = existing_config.masscan_rate if existing_config else "100"
    data["masscan"]["rate"] = int(input(f"  Scan rate (default {default_rate}): ") or default_rate)
    default_target = existing_config.masscan_target if existing_config else ""
    data["masscan"]["target"] = input(f"  Single target IP/domain (optional) [{default_target}]: ") or default_target

    data["database"] = {"path": "workspace/scan.db"}

    print("\n>> Telegram Notifications")
    data["telegram"] = {}
    default_token = existing_config.tg_bot_token if existing_config else ""
    data["telegram"]["bot_token"] = input(f"  Bot token [{default_token}]: ") or default_token
    default_chat = existing_config.tg_chat_id if existing_config else ""
    data["telegram"]["chat_id"] = input(f"  Chat ID [{default_chat}]: ") or default_chat
    default_proxy = existing_config.telegram_proxy if existing_config else ""
    data["telegram"]["proxy"] = input(f"  Proxy (e.g., socks5h://127.0.0.1:9050, or empty) [{default_proxy}]: ") or default_proxy

    print("\n>> OSINT & Targets")
    default_subfinder = existing_config.osint_use_subfinder if existing_config else True
    use_subfinder = input(f"  Use subfinder? (Y/n, default {'Y' if default_subfinder else 'N'}): ").lower()
    data["osint"] = {
        "root_domains": [],
        "use_subfinder": use_subfinder != 'n' if use_subfinder else default_subfinder,
    }
    default_assetfinder = existing_config.osint_use_assetfinder if existing_config else True
    use_assetfinder = input(f"  Use assetfinder? (Y/n, default {'Y' if default_assetfinder else 'N'}): ").lower()
    data["osint"]["use_assetfinder"] = use_assetfinder != 'n' if use_assetfinder else default_assetfinder
    default_amass = existing_config.osint_use_amass if existing_config else False
    use_amass = input(f"  Use amass? (y/N, default {'Y' if default_amass else 'N'}): ").lower()
    data["osint"]["use_amass"] = use_amass == 'y' if use_amass else default_amass

    default_domains = ",".join(existing_config.osint_root_domains) if existing_config and existing_config.osint_root_domains else ""
    domains_input = input(f"  Enter root domains (comma separated) or path to file [{default_domains}]: ") or default_domains
    if os.path.isfile(domains_input):
        data["target_file"] = domains_input
    else:
        data["osint"]["root_domains"] = [d.strip() for d in domains_input.split(",") if d.strip()]
        data["target_file"] = None

    print("\n>> Export")
    default_formats = existing_config.export_settings.get("formats", ["csv", "json", "burp", "maltego"]) if existing_config else ["csv", "json", "burp", "maltego"]
    formats_str = input(f"  Export formats (default {','.join(default_formats)}): ") or ",".join(default_formats)
    data["export"] = {
        "formats": [f.strip() for f in formats_str.split(",") if f.strip()],
        "output_dir": "workspace/exports"
    }

    data["schedule"] = {"interval": 0}

    print("\n>> Additional Modules")
    default_screenshots = existing_config.screenshot_enabled if existing_config else False
    enable_screenshots = input(f"  Enable screenshots (gowitness)? (y/N, default {'Y' if default_screenshots else 'N'}): ").lower()
    data["screenshots"] = {
        "enabled": enable_screenshots == 'y' if enable_screenshots else default_screenshots,
        "output_dir": "workspace/screenshots"
    }
    default_nuclei = existing_config.nuclei_enabled if existing_config else False
    enable_nuclei = input(f"  Enable Nuclei vulnerability scan? (y/N, default {'Y' if default_nuclei else 'N'}): ").lower()
    data["nuclei"] = {"enabled": enable_nuclei == 'y' if enable_nuclei else default_nuclei}
    default_swagger = existing_config.swagger_enabled if existing_config else False
    enable_swagger = input(f"  Enable Swagger parser? (y/N, default {'Y' if default_swagger else 'N'}): ").lower()
    data["swagger"] = {"enabled": enable_swagger == 'y' if enable_swagger else default_swagger}

    data["dashboard"] = {"enabled": False, "host": "127.0.0.1", "port": 5000}

    return data

def main():
    parser = argparse.ArgumentParser(description="Scanoff")
    parser.add_argument("--mode", choices=["osint", "scan", "full", "monitor"], default="full")
    parser.add_argument("--target")
    parser.add_argument("--target-file")
    parser.add_argument("--ports")
    parser.add_argument("--rate", type=int)
    parser.add_argument("--no-waf", action="store_true")
    parser.add_argument("--schedule", type=int)
    parser.add_argument("--config", default="config.yaml")
    parser.add_argument("--dashboard", action="store_true")
    parser.add_argument("--setup", action="store_true")
    parser.add_argument("--interactive", action="store_true")
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()

    show_banner()
    print(f"   {LICENSE}")
    print()

    print("Do you want to check and install required tools? (Y/n): ", end="")
    choice = input().strip().lower()
    if choice == '' or choice == 'y':
        check_and_install_dependencies()
    else:
        print("Skipping dependency check. Some tools may be missing.")

    config_path = args.config
    existing_config = None
    if os.path.exists(config_path):
        existing_config = Config(config_path)

    if args.setup or args.interactive or not os.path.exists(config_path):
        config = Config(config_path)
        data = interactive_config(existing_config)
        config.save(data)
        print(f"[*] Configuration saved to {config_path}.")
        if not args.interactive and not args.setup:
            answer = input("\nDo you want to start scanning now? (Y/n): ").strip().lower()
            if answer == 'n':
                sys.exit(0)
        else:
            sys.exit(0)
    else:
        print("[*] Previous configuration found.")
        choice = input("Use previous configuration? (Y/n/r to reconfigure): ").strip().lower()
        if choice == 'r' or choice == 'n':
            config = Config(config_path)
            data = interactive_config(existing_config)
            config.save(data)
            print(f"[*] Configuration saved to {config_path}.")
            answer = input("\nDo you want to start scanning now? (Y/n): ").strip().lower()
            if answer == 'n':
                sys.exit(0)

    config = Config(config_path)

    if args.target_file:
        config.data["target_file"] = args.target_file
    if args.target:
        config.data["masscan"]["target"] = args.target

    if args.dashboard or config.dashboard_enabled:
        from dashboard import run_dashboard
        run_dashboard(config.dashboard_host, config.dashboard_port)
        return

    db = DatabaseManager(config.db_path)
    waf = None if args.no_waf else WafHandler(initial_delay=0.1, max_delay=5.0, jitter=0.5)
    tech_identifier = TechIdentifier(waf_handler=waf)
    content_analyzer = ContentAnalyzer(waf_handler=waf)

    if args.mode == "osint":
        domains = []
        if config.target_file:
            with open(config.target_file) as f:
                domains = [line.strip() for line in f if line.strip()]
        if config.osint_root_domains:
            domains.extend(config.osint_root_domains)
        if config.masscan_target:
            domains.append(config.masscan_target)
        collector = DomainCollector(
            root_domains=domains,
            use_subfinder=config.osint_use_subfinder,
            use_assetfinder=config.osint_use_assetfinder,
            use_amass=config.osint_use_amass
        )
        osint_data = collector.collect()
        print(f"[*] Subdomains: {osint_data['subdomains']}")
        print(f"[*] IPs: {osint_data['ips']}")
    elif args.mode in ("scan", "full"):
        run_full_scan(config, db, waf, tech_identifier, content_analyzer,
                      masscan_target=args.target, ports=args.ports, rate=args.rate)
    elif args.mode == "monitor":
        from scheduler import Scheduler
        interval = args.schedule if args.schedule else config.schedule_interval
        if interval == 0:
            print("[-] Monitor mode requires a schedule interval (--schedule or config).")
            sys.exit(1)
        scheduler = Scheduler(interval, lambda: run_full_scan(config, db, waf, tech_identifier, content_analyzer,
                                                               masscan_target=args.target, ports=args.ports, rate=args.rate))
        scheduler.start()

if __name__ == "__main__":
    main()
