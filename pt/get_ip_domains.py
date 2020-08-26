#!/usr/bin/env python3
import requests
import os
import sys
import json
import argparse
from passivetotal.libs.dns import DnsRequest

def get_config():
    conf_file = os.path.join(os.path.expanduser("~"), ".config/passivetotal/api_config.json")
    if os.path.isfile(conf_file):
        with open(conf_file, 'r') as f:
            conf = json.loads(f.read())
    else:
        print('No config file')
        sys.exit(1)
    return conf


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Extract all domains from an IP address')
    parser.add_argument('IP', help='an IP address')
    args = parser.parse_args()

    conf = get_config()

    client = DnsRequest(conf['username'], conf['api_key'])
    raw_results = client.get_passive_dns(query=args.IP)
    print("{} domains identified".format(len(raw_results["results"])))

    csvout = open("csv.out", "w+")
    csvout.write("Domain,First,Last,Type\n")
    for r in raw_results["results"]:
        csvout.write("{},{},{},{}\n".format(
            r['resolve'],
            r['firstSeen'],
            r['lastSeen'],
            r['recordType']
        ))
    print("extracted in csv.out")
