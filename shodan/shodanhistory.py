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
        res = api.host(args.IP, history=True)
    except shodan.exception.APIError:
        print("IP not found in Shodan")
    else:
        for d in res['data']:
            if d['port'] == 22:
                print("%s - port 22 ssh - %s\n" % (
                        d['timestamp'],
                        d['data'].split("\n")[0]
                    )
                )
            elif d['port'] == 80:
                print("%s - port 80 http - Server \"%s\"\n" % (
                        d['timestamp'],
                        d['http']['server']
                    )
                )
            elif d['port'] == 443:
                if 'cert' in d['ssl']:
                    print("%s - port 443 https - Cert \"%s\" \"%s\" %s - Server \"%s\"\n" % (
                            d['timestamp'],
                            d['ssl']['cert']['subject']['CN'],
                            d['ssl']['cert']['issuer']['CN'],
                            d['ssl']['cert']['fingerprint']['sha1'],
                            d['http']['server']
                        )
                    )
                else:
                    print("%s - port 443 https - Cert Unknown- Server \"%s\"\n" % (
                            d['timestamp'],
                            d['http']['server']
                        )
                    )
