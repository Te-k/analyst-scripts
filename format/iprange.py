import argparse
import ipaddress


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Convert IP range to IPs')
    parser.add_argument('IPRANGE', help='IP range like 192.168.1.0/24')
    args = parser.parse_args()

    for ip in ipaddress.ip_network(args.IPRANGE, False).hosts():
        print(ip)
