#!/usr/bin/env python3
import shodan
import argparse
import os
import sys
import json
from dateutil.parser import parse
from datetime import datetime, timedelta


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Fingerprint a system based on Shodan information')
    parser.add_argument('IP',  help='IP')
    parser.add_argument('--history', '-H', action='store_true', help='IP')
    parser.add_argument('--key', '-k', help='Shodan API key')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose')

    args = parser.parse_args()

    # Deal with the key first
    if args.key:
        key = args.key
    else:
        cpath = os.path.expanduser('~/.shodan/api_key')
        if os.path.isfile(cpath):
            with open(cpath, 'r') as f:
                key = f.read().strip()
        else:
            print("No API key found")
            sys.exit(1)


    api = shodan.Shodan(key)
    try:
        res = api.host(args.IP, history=args.history)
    except shodan.exception.APIError:
        print("IP not found in Shodan")
    else:
        if args.verbose:
            print(json.dumps(res, sort_keys=False, indent=4))
        else:
            print("%i entries:" % len(res['data']))
            i = 0
            for d in res['data']:
                print(d['timestamp'])
                print(d['_shodan']['module'])
                print("%s/%i" % (d['transport'], d['port']))
                print(d['data'])
                if 'html' in d:
                    print(d['html'])
                if 'http' in d:
                    print(json.dumps(d['http']))
                print('')



