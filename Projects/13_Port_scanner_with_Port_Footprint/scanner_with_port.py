# coding:utf-8

import sys
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from scapy.all import IP, ICMP, sr1
import logging
from queue import Queue

# Suppress Scapy warnings
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

COMMON_SERVICES = { #added as much as found
    # Common System Ports
    20: "FTP-Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP-Server",
    68: "DHCP-Client",
    69: "TFTP",
    80: "HTTP",
    88: "Kerberos",
    110: "POP3",
    123: "NTP",
    137: "NetBIOS-NS",
    138: "NetBIOS-DGM",
    139: "NetBIOS-SSN",
    143: "IMAP",
    161: "SNMP",
    162: "SNMP-Trap",
    179: "BGP",
    194: "IRC",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    514: "Syslog",
    515: "LPD",
    587: "SMTP-Submission",
    636: "LDAPS",

    # Database Ports
    1433: "MSSQL",
    1521: "Oracle-DB",
    2181: "Zookeeper",
    2375: "Docker",
    27017: "MongoDB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    9042: "Cassandra",

    # Web & Application Servers
    8000: "HTTP-Alt",
    8008: "HTTP-Alt2",
    8080: "HTTP-Proxy",
    8081: "HTTP-Alt3",
    8443: "HTTPS-Alt",
    8888: "HTTP-Alt4",
    9000: "PHP-FPM",
    9090: "CockroachDB",

    # Network Services
    11211: "Memcached",
    2049: "NFS",
    2379: "ETCD",
    2380: "ETCD-Peer",
    3000: "NodeJS",
    5000: "UPnP",
    5353: "mDNS",
    5601: "Kibana",
    5900: "VNC",
    6000: "X11",
    6443: "Kubernetes-API",
    6660: "IRC",
    6667: "IRC",
    6697: "IRC-SSL",
    6881: "BitTorrent",
    8005: "Tomcat-Shutdown",
    8088: "FreeIPA",
    8200: "Consul",
    8300: "Consul-Server",
    8444: "VMware-CIM",
    9092: "Kafka",
    9100: "Printer",
    9200: "Elasticsearch",
    9300: "Elasticsearch-Cluster",
    11214: "Memcached-SSL",
    15672: "RabbitMQ",
    25565: "Minecraft",
    27015: "Steam",
    32400: "Plex",

    # Security/VPN
    500: "IPSec",
    1194: "OpenVPN",
    1723: "PPTP",
    1812: "RADIUS",
    1813: "RADIUS-Accounting",
    2083: "cPanel-SSL",
    2087: "WHM-SSL",
    2096: "cPanel-Webmail",
    2222: "DirectAdmin",
    3128: "Squid-Proxy",
    4500: "IPsec-NAT-T",
    5060: "SIP",
    5061: "SIPS",
    5666: "Nagios",
    5938: "TeamViewer",
    5984: "CouchDB",
    5985: "WinRM-HTTP",
    5986: "WinRM-HTTPS",
    7070: "WebLogic",
    7443: "RStudio-SSL",
    7680: "Wazuh",
    8009: "AJP",
    8089: "Splunk",
    8333: "Bitcoin",
    8447: "UniFi",
    8880: "CDDB",
    8883: "MQTT-SSL",
    9001: "Tor",
    9091: "Openfire",
    9200: "Elasticsearch",
    9418: "Git",
    9993: "ZeroTier",
    10000: "Webmin",
    10250: "Kubelet",
    11214: "Memcached-SSL",
    12345: "NetBus",
    13720: "BGP",
    25560: "SaltStack",
    25575: "Minecraft-RCON",
    27015: "Source-Engine",
    31337: "BackOrifice"
}


def detect_os(ip):
    """Perform OS detection once using ICMP TTL"""
    try:
        pkt = sr1(IP(dst=ip) / ICMP(id=RandShort()), timeout=2, verbose=0)
        if pkt and IP in pkt:
            ttl = pkt[IP].ttl
            if ttl <= 64: return "Linux/Unix", ttl
            if ttl == 128: return "Windows", ttl
            if ttl == 255: return "Solaris", ttl
            return "Unknown", ttl
        return "Unknown", None
    except:
        return "OS detection failed", None


def get_service(port, banner):
    """Enhanced service detection with fallback to common ports"""
    # Check banner first
    if 'HTTP' in banner: return 'HTTP'
    if 'FTP' in banner: return 'FTP'
    if 'SSH' in banner: return 'SSH'
    if 'SMTP' in banner: return 'SMTP'
    # Fallback to common ports
    return COMMON_SERVICES.get(port, 'Unknown')


def port_scan(ip, port, results):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            if s.connect_ex((ip, port)) == 0:
                try:
                    banner = s.recv(1024).decode(errors='ignore').strip()
                    service = get_service(port, banner)
                except:
                    service = COMMON_SERVICES.get(port, 'Unknown')
                results.put((port, service))
    except:
        pass


def main():
    if len(sys.argv) != 2:
        print("Usage: python3 scanner.py <target_ip>")
        return

    target = sys.argv[1]
    results = Queue()

    # OS detection (single check)
    os_info, ttl = detect_os(target)

    # Port scanning
    with ThreadPoolExecutor(max_workers=100) as executor:
        print(f"Scanning {target}...", end='', flush=True)
        futures = [executor.submit(port_scan, target, port, results)
                   for port in range(1, 65536)]
        for _ in as_completed(futures): pass
        print(" Done")

    # Get sorted results
    open_ports = sorted(results.queue, key=lambda x: x[0])

    # Display results
    print(f"\nTarget: {target}")
    print(f"Detected OS: {os_info} (TTL: {ttl if ttl else 'N/A'})")
    print("\nOpen ports:")
    for port, service in open_ports:
        print(f"Port {port}: {service}")


if __name__ == "__main__":
    main()