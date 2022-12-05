import ipaddress
import argparse

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Process an IP')
    parser.add_argument('IP')
    args = parser.parse_args()

    if "." in args.IP:
        ip = ipaddress.IPv4Address(args.IP)
        print(int(ip))
    else:
        ip = ipaddress.IPv4Address(int(args.IP))
        print(str(ip))
