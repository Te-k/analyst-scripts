#!/usr/bin/env python3
import argparse
import dns.resolver
import ipaddress
import sys
import requests


#------------------------- Google Cloud IPs -----------------------------------
# See _cloud-netblocks.googleusercontent.com
def google_dns_query(domain):
    """
    Do a dns query and return domains, cidrs
    """
    cidrs = []
    domains = []
    answers = dns.resolver.query(domain, 'TXT')
    for a in answers:
        for entry in a.to_text().split(" "):
            if entry.startswith('include:'):
                domains.append(entry[8:])
            elif entry.startswith('ip4:'):
                cidrs.append(ipaddress.ip_network(entry[4:]))
            elif entry.startswith('ip6:'):
                cidrs.append(ipaddress.ip_network(entry[4:]))
    for d in domains:
        cidrs.extend(google_dns_query(d))
    return cidrs

def google_ranges():
    """
    Return google cloud CIDRs
    """
    return google_dns_query('_cloud-netblocks.googleusercontent.com')

def aws_ranges():
    """
    Return AWS ranges
    https://ip-ranges.amazonaws.com/ip-ranges.json
    """
    r = requests.get('https://ip-ranges.amazonaws.com/ip-ranges.json')
    data = r.json()
    ranges = []
    for d in data['prefixes']:
        ranges.append(ipaddress.ip_network(d['ip_prefix']))
    return ranges


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Process some Cloud IP ranges')
    parser.add_argument('--ip', '-i', help='Check if an IP is in a cloud IP range')
    parser.add_argument('--list', '-l',  help='Check if IPs from a file are in a Cloud IP range')
    parser.add_argument('--show', '-s',  action='store_true', help='Print the list of IP ranges')
    args = parser.parse_args()

    providers = {
        'Google Cloud': google_ranges(),
        'Amazon AWS': aws_ranges()
    }

    if args.show:
        for p in providers:
            print('### %s' % p)
            for d in providers[p]:
                print(d)
    elif args.ip:
        ip = ipaddress.ip_address(args.ip)
        for p in providers:
            for d in providers[p]:
                if ip in d:
                    print("%s - %s (%s)" % (args.ip, p, d))
                    sys.exit(0)
        print('IP not found')
    elif args.list:
        with open(args.list, 'r') as f:
            ips = f.read().split("\n")
            for ip in ips:
                if ip.strip() != '':
                    try:
                        ipp = ipaddress.ip_address(ip)
                        found = False
                        for p in providers:
                            for iprange in providers[p]:
                                if ipp in iprange:
                                    print("%s ; %s" % (ip, p))
                                    found = True
                                    break
                        if not found:
                            print("%s ; Not found" % ip)
                    except ValueError:
                        print("%s ; Not an IP address" % ip)
    else:
        print("Please give either an IP (-i), a list (-l) or show the full list (-s)")
        parser.print_help()
