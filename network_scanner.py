import scapy.all as sc
import argparse
import csv
import sys
import requests

#argument parser 
def get_arguments():
    parser = argparse.ArgumentParser(
        description="ARP Network Scanner"
    )
    parser.add_argument(
        "-t", "--target",
        dest="target",
        required=True,
        help="Target IP / IP range (e.g., 192.168.1.0/24)"
    )
    parser.add_argument(
        "-o", "--output",
        dest="output",
        help="Save results to CSV file"
    )
    return parser.parse_args()


#vendor lookup
def get_vendor(mac):
    try:
        url = f"https://api.macvendors.com/{mac}"
        response = requests.get(url, timeout=3)

        if response.status_code == 200:
            return response.text
        else:
            return "Unknown"
    except requests.RequestException:
        return "Unknown"


# scanner 
def scan(ip_range):
    try:
        arp_req = sc.ARP(pdst=ip_range)
        broadcast = sc.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_req_broadcast = broadcast / arp_req

        answered = sc.srp(
            arp_req_broadcast,
            timeout=2,
            verbose=False
        )[0]

        clients = []

        for sent, received in answered:
            vendor = get_vendor(received.hwsrc)

            clients.append({
                "ip": received.psrc,
                "mac": received.hwsrc,
                "vendor": vendor
            })

        return clients

    except PermissionError:
        print("[-] Run this script with sudo/root privileges.")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Scan error: {e}")
        sys.exit(1)


#print results ----------------------
def print_result(results):
    print("\nIP Address\t\tMAC Address\t\tVendor")
    print("-" * 70)

    for client in results:
        print(f"{client['ip']}\t{client['mac']}\t{client['vendor']}")

    print("-" * 70)
    print(f"[+] Hosts discovered: {len(results)}")


#save to CSV 
def save_to_csv(results, filename):
    try:
        with open(filename, "w", newline="") as csvfile:
            writer = csv.DictWriter(
                csvfile,
                fieldnames=["ip", "mac", "vendor"]
            )
            writer.writeheader()
            writer.writerows(results)

        print(f"[+] Results saved to {filename}")

    except Exception as e:
        print(f"[-] Failed to save CSV: {e}")


# main
if __name__ == "__main__":
    options = get_arguments()

    print("[*] Scanning network...")
    scan_result = scan(options.target)

    print_result(scan_result)

    if options.output:
        save_to_csv(scan_result, options.output)