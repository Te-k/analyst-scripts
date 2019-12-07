#! /usr/bin/env python
import sys
import argparse
import json
import requests


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Process some integers.')
    parser.add_argument('DOMAIN',  help='Domain to be checked')
    parser.add_argument('--type', '-t', default='A',  help='DNS Type')
    parser.add_argument('--verbose', '-v', action='store_true',  help='Display results')
    args = parser.parse_args()

    params = {
        'name': args.DOMAIN,
        'type': args.type,
        'ct': 'application/dns-json',
    }
    r = requests.get("https://dns.quad9.net:5053/dns-query", params=params)
    if r.status_code != 200:
        print('Problem querying quad9 :(')
        sys.exit(1)
    if r.json()['Status'] == 3:
        print("{} - BLOCKED".format(args.DOMAIN))
    else:
        print("{} - NOT BLOCKED".format(args.DOMAIN))
    if args.verbose:
        print(json.dumps(r.json(), indent=4))
