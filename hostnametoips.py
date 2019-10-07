#!/usr/bin/env python3
import dns.resolver
import argparse

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Resolve domains and get list of IPs')
    parser.add_argument('FILE', help='File containing list of domains')
    parser.add_argument('--verbose', '-v', action='store_true',
            help='File containing list of domains')
    args = parser.parse_args()

    with open(args.FILE) as f:
        data = f.read().split('\n')

    res = dns.resolver.Resolver()

    ips = set()
    for d in data:
        if d.strip != '':
            try:
                ans = res.query(d.strip(), "A")
                for ip in ans:
                    if args.verbose:
                        print("%s - %s" % (d.strip(), ip.to_text()))
                    ips.add(ip.to_text())
            except dns.resolver.NXDOMAIN:
                if args.verbose:
                    print("%s - no domain" % d.strip())

    for ip in ips:
        print(ip)
