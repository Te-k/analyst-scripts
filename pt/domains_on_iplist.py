import argparse
import os
import sys
import json
import dns.resolver
import requests
from datetime import datetime, timezone, timedelta
from dns import resolver, reversename, exception

PT_BASE_URL = "https://api.passivetotal.org"
DEFAULT_TIMEFRAME = 365

def get_unique_dns(config, ip_address, start=None):
    if not start:
        start_date = datetime.now() - timedelta(days=DEFAULT_TIMEFRAME)
        start = start_date.strftime("%Y-%m-%d %H:%M:%S")

    path = "/v2/dns/passive/unique"
    results = passivetotal_get(config, path, ip_address, start)

    domains = []
    if "results" in results:
        for domain in results["results"]:
            if domain not in domains:
                domains.append(domain)

    return domains


def passivetotal_get(conf, path, query, start):
    url = PT_BASE_URL + path
    data = {"query": query, "start": start}
    PT_AUTH = (conf['username'], conf['api_key'])
    response = requests.get(url, auth=PT_AUTH, json=data)
    return response.json()


def resolve_domain(domain):
    resolutions = []
    try:
        answer = resolver.query(domain, "A")
        for ip in answer:
            resolutions.append(ip.address)
    except (resolver.NoAnswer, resolver.NXDOMAIN, resolver.NoNameservers, exception.Timeout):
        pass

    return resolutions

def get_config():
    conf_file = os.path.join(os.path.expanduser("~"), ".config/passivetotal/api_config.json")
    if os.path.isfile(conf_file):
        with open(conf_file, 'r') as f:
            conf = json.loads(f.read())
    else:
        print('No config file')
        sys.exit(1)
    return conf


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Get list of domains on a list of IPs')
    parser.add_argument('IPFILE', help='File with a list of IPs')
    args = parser.parse_args()

    config = get_config()

    with open(args.IPFILE) as f:
        ips = f.read().split('\n')
    ips.remove('')

    blocked_domains = set()
    for ip in ips:
        print("Checking {}".format(ip))
        domains = get_unique_dns(config, ip)
        for d in domains:
            sips = resolve_domain(d)
            if ip in sips:
                print("{} still on {}".format(d, ip))
                blocked_domains.add(d)
            else:
                print("{} not anymore on {}".format(d, ip))

    with open("a.txt", "w+") as f:
        for d in blocked_domains:
            f.write("{}\n".format(d))
