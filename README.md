# Python ARP Network Scanner 

A Python-based network discovery tool that performs ARP scanning to identify live hosts on a local network and enriches results with MAC vendor information.

This project demonstrates practical understanding of Layer 2 reconnaissance, network enumeration, and basic security automation.

---

## Features

* ARP based host discovery using Scapy
* MAC address vendor enrichment
* Command-line interface using argparse
* Optional CSV export for reporting
* Basic error handling
* Fast and lightweight network scanning

---

## Technologies Used

* Python
* Scapy
* argparse
* requests
* CSV module

---

## Requirements

* Python 3
* Root / sudo privileges (required for ARP scanning)
* Linux recommended (Kali Linux preferred)

Install dependencies:

```bash
pip install scapy requests
```

---

## Usage

### Basic Scan

```bash
sudo python scanner.py -t 192.168.1.0/24
```

### Scan and Save Results

```bash
sudo python scanner.py -t 192.168.1.0/24 -o results.csv
```

---

## Sample Output

```
IP Address        MAC Address        Vendor
------------------------------------------------------
192.168.1.1       aa:bb:cc:dd:ee:ff  Cisco Systems
192.168.1.5       11:22:33:44:55:66  Samsung Electronics
------------------------------------------------------
[+] Hosts discovered: 2
```

---

## Learning Outcomes

* Understanding of ARP protocol and Layer 2 discovery
* Practical experience with Scapy packet crafting
* Network enumeration fundamentals
* Security automation using Python
* Basic asset visibility techniques used in SOC environments

---

## Disclaimer

This tool is intended for **educational and authorized security testing purposes only**.
Do not use this tool on networks without proper permission.

---

## Future Improvements

* Interface selection
* Multithreaded scanning
* Hostname resolution
* Enhanced reporting

---

## Author

**Hruthik N**
LinkedIn: [www.linkedin.com/in/hruthik-n](http://www.linkedin.com/in/hruthik-n)
