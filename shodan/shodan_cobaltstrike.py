#!/usr/bin/env python3
import shodan
import argparse
import os
import sys
import json
from dateutil.parser import parse
from datetime import datetime, timedelta


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Extract list of Cobalt Strike servers from Shodan')
    parser.add_argument('--key', '-k', help='Shodan API key')
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
        # Cobalt Strike JARM signature
        res = api.search("ssl.jarm:07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1")
    except shodan.exception.APIError:
        print("IP not found in Shodan")
    else:
        for ip in res['matches']:
            print(ip['ip_str'])
