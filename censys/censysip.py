#!/usr/bin/env python2
# -*- coding: utf-8 -*-
import censys.ipv4
import os
import argparse
import json
from censyslib import *


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Request censys IPv4 database')
    parser.add_argument('--search', '-s', help='Search term in Censys database')
    parser.add_argument('--ip', '-i', help='Check info on the given IP')
    parser.add_argument('--max-results', '-m', default=100, type=int, help='Max number of results')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose mode')
    args = parser.parse_args()

    key = get_apikey()

    cc = censys.ipv4.CensysIPv4(api_id=key[0], api_secret=key[1])

    if args.search is not None:
        it = cc.search(args.search)
        results = []
        try:
            for i in range(args.max_results):
                results.append(it.next())
        except StopIteration:
                pass

        # print IP list
        for ip in results:
            print(ip['ip'])
    elif args.ip is not None:
        ip = cc.view(args.ip)
        print(json.dumps(ip, sort_keys=True, indent=4, separators=(',', ': ')))
    else:
        parser.print_help()

