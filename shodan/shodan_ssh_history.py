#!/usr/bin/env python3
import shodan
import argparse
import os
import sys
import json
from dateutil.parser import parse
from datetime import datetime, timedelta
from dateutil import parser


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Fingerprint a system based on Shodan information')
    parser.add_argument('IP',  help='IP')
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
    data = {}
    try:
        res = api.host(args.IP, history=True)
    except shodan.exception.APIError:
        print("IP not found in Shodan")
    else:
        for event in res['data']:
            if event['_shodan']['module'] == 'ssh':
                fingerprint = event['ssh']['fingerprint']
                date = parse(event['timestamp'])
                if fingerprint not in data:
                    data[fingerprint] = {'first': date, 'last': date, 'fingerprint': fingerprint}
                else:
                    if data[fingerprint]['first'] > date:
                        data[fingerprint]['first'] = date
                    if data[fingerprint]['last'] < date:
                        data[fingerprint]['last'] = date

    for val in sorted(data.values(), key=lambda x:x['first']):
        print('%s - %s -> %s' % (
                val['fingerprint'],
                val['first'].strftime('%Y-%m-%d'),
                val['last'].strftime('%Y-%m-%d')
            )
        )
