import ipaddress
import argparse

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Show first and last IP address in an IP range")
    parser.add_argument("IPRANGE", help="IP range")
    args = parser.parse_args()

    l = list(ipaddress.ip_network(args.IPRANGE))
    print(l[0])
    print(l[-1])
