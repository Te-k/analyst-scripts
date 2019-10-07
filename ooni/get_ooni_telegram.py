#!/usr/bin/env python3
import argparse
import requests
from datetime import datetime, timedelta
from colored import fg, bg, attr

class OoniError(Exception):
    pass

class OoniRepository(object):
    def __init__(self):
        self.base_url = "https://api.ooni.io/api/v1/"

    def list_tests(self, since, until, test, country):
        # TODO: handle pagination
        r = requests.get(
                self.base_url + "files",
                params={
                    'probe_cc':country,
                    'since': since.strftime("%Y-%m-%dT%H:%M:%S"),
                    'until': until.strftime("%Y-%m-%dT%H:%M:%S"),
                    'test_name': test
                    }
            )
        if r.status_code == 200:
            return r.json()
        else:
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


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Check OONI data')
    parser.add_argument('--country', '-c', default="IR",
            help="Country to check")
    parser.add_argument('--day', '-d', nargs='?',
            help='Day to consider (format YYYYMMDD)')
    args = parser.parse_args()

    if args.day:
        since = datetime.strptime(args.day, "%Y%m%d")
    else:
        now = datetime.now()
        since = datetime(now.year, now.month, now.day) - timedelta(days=1)

    until = since + timedelta(days=1)

    ooni = OoniRepository()
    results = ooni.list_tests(since, until, "telegram", args.country)

    # Organize per ASN
    asns = {}
    for r in results['results']:
        if r['probe_asn'] in asns:
            asns[r['probe_asn']].append(r)
        else:
            asns[r['probe_asn']] = [r]

    # Analyze stuff
    for asn in asns:
        print("%s%s# %s%s" % (fg('white'), bg('yellow'), asn.upper(), attr(0)))
        for r in sorted(asns[asn], key=lambda x: x['test_start_time']):
            data = ooni.download_file(r['download_url'])
            colors = {'KO': 'red', 'OK': 'green', 'None': 249}
            if data['test_keys']['telegram_http_blocking'] is None:
                http_blocking = "None"
            else:
                if data['test_keys']['telegram_http_blocking']:
                    http_blocking = 'KO'
                else:
                    http_blocking = 'OK'
            print("%s\t %sHTTP: %s\t%sTCP: %s\t\t%sWeb: %s%s" % (
                    r['test_start_time'],
                    fg(colors[http_blocking]),
                    http_blocking,
                    fg('red') if data['test_keys']['telegram_tcp_blocking'] else fg('green'),
                    "KO" if data['test_keys']['telegram_tcp_blocking'] else "OK",
                    fg('red') if data['test_keys']['telegram_web_status'] != 'ok' else fg('green'),
                    data['test_keys']['telegram_web_status'],
                    attr(0)
                    )
            )
        print("")

