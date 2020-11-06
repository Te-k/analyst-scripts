#!/usr/bin/env python3
import requests
import os
import sys
import json
import argparse
from passivetotal.libs.dns import DnsRequest
from passivetotal.libs.enrichment import EnrichmentRequest

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
    parser = argparse.ArgumentParser(description='List subdomains for a domain')
    parser.add_argument('DOMAIN', help='Domain')
    args = parser.parse_args()

    conf = get_config()

    client = EnrichmentRequest(conf['username'], conf['api_key'])
    raw_results = client.get_subdomains(query=args.DOMAIN)
    for s in raw_results['subdomains']:
        print(s + '.' + raw_results['primaryDomain'])
