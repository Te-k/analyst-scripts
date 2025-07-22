#!/usr/bin/env python3
import shodan
import argparse
import os
import sys
from dateutil.parser import parse
from dateutil import parser


if __name__ == '__main__':
    # Arguments with argparse
    parser = argparse.ArgumentParser(description='Fingerprint a system based on Shodan information')
    parser.add_argument('IP',  help='IP')
    parser.add_argument('--key', '-k', help='Shodan API key')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose')
    args = parser.parse_args()

    # Deal with the key first, either from the arguments or from the
    # standard file used by the shodan tool
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

    # creates the API object with the key as parameter
    api = shodan.Shodan(key)
    data = {}
    try:
        # Get all the data on this host
        res = api.host(args.IP, history=True)
    except shodan.exception.APIError:
        # Raises an exception if the IP has no data
        print("IP not found in Shodan")
        sys.exit(0)

    # Go through the data
    for event in res['data']:
        if event['_shodan']['module'] != 'ssh':
            continue

        fingerprint = event['ssh']['fingerprint']
        date = parse(event['timestamp'])
        if fingerprint not in data:
            data[fingerprint] = {'first': date, 'last': date, 'fingerprint': fingerprint}
        else:
            if data[fingerprint]['first'] > date:
                data[fingerprint]['first'] = date
            if data[fingerprint]['last'] < date:
                data[fingerprint]['last'] = date

    # Print the result
    for val in sorted(data.values(), key=lambda x:x['first']):
        print('%s - %s -> %s' % (
                val['fingerprint'],
                val['first'].strftime('%Y-%m-%d'),
                val['last'].strftime('%Y-%m-%d')
            )
        )
