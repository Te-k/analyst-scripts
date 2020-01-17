#!/usr/bin/env python3
import argparse
import requests
import sys
import time
from datetime import datetime, timedelta
from colored import fg, bg, attr

class OoniError(Exception):
    pass

class OoniRepository(object):
    def __init__(self):
        self.base_url = "https://api.ooni.io/api/v1/"

    def list_tests(self, since, until, test, country, domain):
        # TODO: handle pagination
        params={
            'probe_cc':country,
            'since': since.strftime("%Y-%m-%d"),
            'until': until.strftime("%Y-%m-%d"),
            'test_name': test,
            'domain': domain
        }
        r = requests.get(self.base_url + "measurements", params=params)
        if r.status_code == 200:
            return r.json()
        else:
            print(r)
            raise OoniError()

    def download_file(self, url):
        """
        Download a given OONI file
        """
        r = requests.get(url)
        if r.status_code == 200:
            return r.json()
        else:
            raise OoniError()

    def extract_dns_answer(self, data):
        """
        Extract DNS A answer from OONI web measurement
        if it does not exist; returns []
        """
        res = set()
        if "test_keys" in data:
            if "queries" in data["test_keys"]:
                for q in data["test_keys"]["queries"]:
                    for a in q["answers"]:
                        if a["answer_type"] == "A":
                            res.add(a["ipv4"])
        return list(res)

    def extract_dns_server(self, data):
        """
        Extract the DNS server used by the query
        """
        if "test_keys" in data:
            if "client_resolver" in data["test_keys"]:
                return data["test_keys"]["client_resolver"]
        return ""

    def extract_url(self, data):
        if "test_keys" in data:
            if "requests" in data["test_keys"]:
                return data['test_keys']['requests'][0]['request']['url']


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Check OONI data')
    parser.add_argument('--country', '-c',
            help="Country to check")
    parser.add_argument('--since', '-s', nargs='?',
            help='The start date of when measurements were run (format YYYYMMDD)')
    parser.add_argument('--until', '-u', nargs='?',
            help='The end date of when measurement were run (format YYYYMMDD)')
    args = parser.parse_args()

    SIGNAL_DOMAINS = ['textsecure-service.whispersystems.org', 'storage.signal.org', 'api.directory.signal.org', 'api.backup.signal.org', 'contentproxy.signal.org']

    if not args.country:
        print("Please provide a country code")
        sys.exit(-1)

    if args.since:
        since = datetime.strptime(args.since, "%Y%m%d")
    else:
        now = datetime.now()
        since = datetime(now.year, now.month, now.day) - timedelta(days=1)

    if args.until:
        until = datetime.strptime(args.until, "%Y%m%d")
    else:
        until = datetime.now()

    if since > until:
        since, until = until, since

    ooni = OoniRepository()
    results = []
    for d in SIGNAL_DOMAINS:
        r = ooni.list_tests(
            since,
            until,
            "web_connectivity",
            args.country,
            d
        )
        results += r["results"]
        time.sleep(0.5)

    if len(results) == 0:
        print("No measurement found")
        sys.exit(0)

    # Organize per ASN
    asns = {}
    for r in results:
        if r['probe_asn'] in asns:
            asns[r['probe_asn']].append(r)
        else:
            asns[r['probe_asn']] = [r]

    # Analyze stuff
    for asn in asns:
        print("%s%s# %s%s" % (fg('white'), bg('yellow'), asn.upper(), attr(0)))
        for r in sorted(asns[asn], key=lambda x: x['measurement_start_time']):
            data = ooni.download_file(r['measurement_url'])
            dns_server = ooni.extract_dns_server(data)
            ips = ooni.extract_dns_answer(data)
            colors = {'Yes': 'red', 'No': 'green', 'None': 249}
            print("%s\t%s\t%sAnomaly: %s\t%sConfirmed: %s%s (DNS: %s | IP: %s)" % (
                    r['measurement_start_time'],
                    ooni.extract_url(data),
                    fg(colors['Yes']) if r["anomaly"] else fg(colors['No']),
                    'Yes' if r["anomaly"] else "No",
                    fg('red') if r["confirmed"] else fg('green'),
                    "Yes" if r["confirmed"] else "No",
                    attr(0),
                    dns_server,
                    ",".join(ips)
                    )
            )
        print("")

