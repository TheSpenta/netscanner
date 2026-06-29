#!/usr/bin/env python3
import subprocess
import sys
import json
from datetime import datetime

def scan_host(ip):
    result = subprocess.run(
        ["nmap", "-T4", "--open", "-F", ip],
        capture_output=True, text=True
    )
    ports = []
    for line in result.stdout.splitlines():
        if "/tcp" in line or "/udp" in line:
            parts = line.split()
            ports.append({"port": parts[0], "state": parts[1], "service": parts[2]})
    return ports

def sweep_network(subnet):
    result = subprocess.run(
        ["nmap", "-sn", subnet],
        capture_output=True, text=True
    )
    hosts = []
    for line in result.stdout.splitlines():
        if "Nmap scan report for" in line:
            parts = line.split()
            hostname = parts[4] if len(parts) == 6 else "unknown"
            ip = parts[-1].strip("()")
            hosts.append({"ip": ip, "hostname": hostname})
    return hosts

def print_report(results, duration):
    print(f"\n{'='*52}")
    print(f"  SCAN REPORT — {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    print(f"{'='*52}")
    for host in results:
        label = f"{host['ip']}"
        if host['hostname'] != "unknown" and host['hostname'] != host['ip']:
            label += f" ({host['hostname']})"
        print(f"\n  Host : {label}")
        if host['ports']:
            for p in host['ports']:
                print(f"    {p['port']:<18} {p['state']:<8} {p['service']}")
        else:
            print(f"    no open ports found")
    print(f"\n{'='*52}")
    print(f"  {len(results)} host(s) scanned in {duration}s")
    print(f"{'='*52}\n")

def save_report(results, subnet):
    filename = f"scan_{subnet.replace('/','-')}_{datetime.now().strftime('%Y%m%d_%H%M')}.json"
    with open(filename, "w") as f:
        json.dump({"subnet": subnet, "timestamp": str(datetime.now()), "hosts": results}, f, indent=2)
    print(f"  [+] Report saved to {filename}\n")

if __name__ == "__main__":
    subnet = sys.argv[1] if len(sys.argv) > 1 else "10.200.190.0/24"
    start = datetime.now()

    print(f"\n[*] Scanning {subnet} ...")
    hosts = sweep_network(subnet)
    print(f"[+] Found {len(hosts)} live host(s) — scanning ports...\n")

    results = []
    for host in hosts:
        ports = scan_host(host["ip"])
        results.append({**host, "ports": ports})

    duration = (datetime.now() - start).seconds
    print_report(results, duration)
    save_report(results, subnet)
