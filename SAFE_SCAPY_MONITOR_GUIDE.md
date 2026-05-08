# Safe Scapy Traffic Monitor Guide

This guide adds a defensive Scapy component to the project. It does not perform ARP spoofing, DNS spoofing, or Man-in-the-Middle attacks. It monitors ARP and DNS traffic so you can explain what suspicious redirection evidence looks like in a controlled lab.

## Install

```powershell
pip install -r requirements.txt
```

On Windows, Scapy packet capture may require Npcap. Wireshark usually installs Npcap already.

## Run The Monitor

Watch for DNS traffic involving `secure-login.com`:

```powershell
python .\scapy_traffic_monitor.py --domain secure-login.com
```

If you know your local lab web server IP, include it:

```powershell
python .\scapy_traffic_monitor.py --domain secure-login.com --expected-ip 127.0.0.1
```

If Scapy needs a specific interface, list interfaces with:

```powershell
python -m scapy
```

Then inside Scapy:

```python
show_interfaces()
```

Run with an interface:

```powershell
python .\scapy_traffic_monitor.py --interface "Adapter for loopback traffic capture" --domain secure-login.com --expected-ip 127.0.0.1
```

## Safe DNS Redirection Demo

For a safe classroom demo, avoid hijacking another machine's traffic. Instead, use one of these controlled options:

- Add a temporary local hosts-file entry on your own test VM.
- Configure the test VM to use a DNS server you control.
- Use `secure-login.com` as a local lab-only demonstration name.

After the demo, remove the hosts-file entry or restore DNS settings.

## Wireshark Filters

Show all DNS traffic:

```text
dns
```

Show DNS queries for the target domain:

```text
dns.qry.name == "secure-login.com"
```

Show DNS A-record answers:

```text
dns.flags.response == 1 && dns.a
```

Show DNS answers that point to your lab server:

```text
dns.flags.response == 1 && dns.qry.name == "secure-login.com" && dns.a == 127.0.0.1
```

Show ARP traffic:

```text
arp
```

Show ARP replies only:

```text
arp.opcode == 2
```

## What To Say In The Presentation

DNS redirection is proven when a DNS response for `secure-login.com` returns the lab server IP instead of the real public IP. ARP monitoring is useful because unexpected MAC address changes for the same IP can indicate a possible local network spoofing attempt.

The safe learning point is:

> Traffic analysis can reveal when name resolution or local network address mapping has been manipulated. HTTPS protects payload contents, but users can still be redirected if DNS or routing is compromised.
