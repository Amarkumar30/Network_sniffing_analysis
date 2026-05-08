import argparse
from datetime import datetime

from scapy.all import ARP, DNS, DNSQR, DNSRR, IP, sniff


DEFAULT_DOMAIN = "secure-login.com"


def now():
    return datetime.now().strftime("%H:%M:%S")


def normalize_domain(name):
    if isinstance(name, bytes):
        name = name.decode("utf-8", errors="replace")
    return name.rstrip(".").lower()


class TrafficMonitor:
    def __init__(self, target_domain, expected_ip=None):
        self.target_domain = target_domain.rstrip(".").lower()
        self.expected_ip = expected_ip
        self.arp_table = {}

    def handle_packet(self, packet):
        if packet.haslayer(ARP):
            self.handle_arp(packet)
        if packet.haslayer(DNS):
            self.handle_dns(packet)

    def handle_arp(self, packet):
        arp = packet[ARP]
        if arp.op not in (1, 2):
            return

        ip_addr = arp.psrc
        mac_addr = arp.hwsrc
        old_mac = self.arp_table.get(ip_addr)
        event = "ARP request" if arp.op == 1 else "ARP reply"

        if old_mac and old_mac != mac_addr:
            print(
                f"[{now()}] ARP WARNING: {ip_addr} changed MAC "
                f"from {old_mac} to {mac_addr}"
            )
            print("         This can indicate ARP spoofing or a legitimate network change.")
        else:
            print(f"[{now()}] {event}: {ip_addr} is at {mac_addr}")

        self.arp_table[ip_addr] = mac_addr

    def handle_dns(self, packet):
        dns = packet[DNS]

        if dns.qr == 0 and packet.haslayer(DNSQR):
            query = normalize_domain(packet[DNSQR].qname)
            if query == self.target_domain:
                src = packet[IP].src if packet.haslayer(IP) else "unknown"
                print(f"[{now()}] DNS query: {src} asked for {query}")
            return

        if dns.qr != 1:
            return

        query = normalize_domain(dns.qd.qname) if dns.qd else ""
        if query != self.target_domain:
            return

        answers = []
        for index in range(dns.ancount):
            answer = dns.an[index]
            if isinstance(answer, DNSRR) and answer.type == 1:
                answers.append(answer.rdata)

        src = packet[IP].src if packet.haslayer(IP) else "unknown"
        dst = packet[IP].dst if packet.haslayer(IP) else "unknown"
        print(f"[{now()}] DNS answer: {src} -> {dst} resolved {query} to {answers}")

        if self.expected_ip and self.expected_ip in answers:
            print(f"         MATCH: {query} points to expected lab server {self.expected_ip}")
        elif self.expected_ip and answers:
            print(f"         NOTICE: expected {self.expected_ip}, but saw {answers}")


def parse_args():
    parser = argparse.ArgumentParser(
        description="Defensive Scapy monitor for ARP changes and DNS redirection evidence."
    )
    parser.add_argument(
        "-i",
        "--interface",
        help="Network interface to sniff. Omit to let Scapy choose the default.",
    )
    parser.add_argument(
        "-d",
        "--domain",
        default=DEFAULT_DOMAIN,
        help=f"Domain to watch. Default: {DEFAULT_DOMAIN}",
    )
    parser.add_argument(
        "-e",
        "--expected-ip",
        help="Expected lab web server IP for the watched domain.",
    )
    parser.add_argument(
        "-c",
        "--count",
        type=int,
        default=0,
        help="Number of packets to capture. Default 0 means run until Ctrl+C.",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    monitor = TrafficMonitor(args.domain, args.expected_ip)
    capture_filter = "arp or udp port 53 or tcp port 53"

    print("Scapy traffic monitor started.")
    print(f"Watching domain: {args.domain}")
    if args.expected_ip:
        print(f"Expected lab server IP: {args.expected_ip}")
    print(f"Capture filter: {capture_filter}")
    print("Press Ctrl+C to stop.")
    print()

    try:
        sniff(
            iface=args.interface,
            filter=capture_filter,
            prn=monitor.handle_packet,
            store=False,
            count=args.count,
        )
    except PermissionError:
        print("Permission denied. Run the terminal as Administrator/root for packet capture.")
    except KeyboardInterrupt:
        print("\nMonitor stopped.")


if __name__ == "__main__":
    main()
