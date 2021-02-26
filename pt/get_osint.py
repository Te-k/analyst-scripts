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
    parser = argparse.ArgumentParser(description='Get OSINT from PT for domains')
    parser.add_argument('FILE', help='File with list of domains')
    args = parser.parse_args()

    conf = get_config()

    with open(args.FILE, 'r') as f:
        domains = list(set([d.strip() for d in f.read().split()]))

    client = EnrichmentRequest(conf['username'], conf['api_key'])

    for domain in domains:
        if domain == '':
            continue
        print(f"################ {domain}")
        try:
            raw_results = client.get_osint(query=domain)
            if raw_results['success']:
                for s in raw_results['results']:
                    print(s)
            else:
                print("Request failed")
        except:
            print("Something failed")
