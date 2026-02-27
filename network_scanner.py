import scapy.all as sc
import optparse

def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target", dest="target",help="Target IP / IP range (e.g., 192.168.1.0/24)")
    
    (options, arguments) = parser.parse_args()

    if not options.target:
        parser.error("[-] Please specify a target. Use --help for more info.")

    return options


def scan(ip_range):
    arp_req = sc.ARP(pdst=ip_range)
    broadcast = sc.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_req_broadcast = broadcast / arp_req

    ans_list = sc.srp(arp_req_broadcast, timeout=1, verbose=False)[0]

    client_list = []
    for sent, received in ans_list:
        client_list.append({
            "ip": received.psrc,
            "mac": received.hwsrc
        })

    return client_list


def print_result(results):
    print("IP Address\t\tMAC Address")
    print("-" * 40)
    for client in results:
        print(f"{client['ip']}\t\t{client['mac']}")
    print("-" * 40)


if __name__ == "__main__":
    options = get_arguments()
    scan_result = scan(options.target)
    print_result(scan_result)