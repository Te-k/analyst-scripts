import argparse
import requests
from datetime import datetime, timedelta
from colored import fg, bg, attr

class OoniError(Exception):
    pass

class OoniRepository(object):
    def __init__(self):
        self.base_url = "https://api.ooni.io/api/v1/"

    def list_tests(self, since, until, test, country, input):
        # TODO: handle pagination
        r = requests.get(
                self.base_url + "measurements",
                params={
                    'probe_cc':country,
                    'since': since.strftime("%Y-%m-%dT%H:%M:%S"),
                    'until': until.strftime("%Y-%m-%dT%H:%M:%S"),
                    'test_name': test,
                    'input': input
                    }
            )
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


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Check OONI data')
    parser.add_argument('--country', '-c',
            help="Country to check")
    parser.add_argument('--day', '-d', nargs='?',
            help='Day to consider (format YYYYMMDD)')
    parser.add_argument('--website', '-w',
            help='Day to consider (format YYYYMMDD)')
    args = parser.parse_args()

    if not args.country:
        print("Please provide a country code")
        sys.exit(-1)
    if not args.website:
        print("Please provide a website")
        sys.exit(-1)

    if args.day:
        since = datetime.strptime(args.day, "%Y%m%d")
    else:
        now = datetime.now()
        since = datetime(now.year, now.month, now.day) - timedelta(days=1)

    until = since + timedelta(days=1)

    ooni = OoniRepository()
    results = ooni.list_tests(
        since,
        until,
        "web_connectivity",
        args.country,
        args.website
    )

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
        for r in sorted(asns[asn], key=lambda x: x['measurement_start_time']):
            data = ooni.download_file(r['measurement_url'])
            ips = ooni.extract_dns_answer(data)
            colors = {'Yes': 'red', 'No': 'green', 'None': 249}
            print("%s\t %sAnomaly: %s\t%sConfirmed: %s%s (IP: %s)" % (
                    r['measurement_start_time'],
                    fg(colors['Yes']) if r["anomaly"] else fg(colors['No']),
                    'Yes' if r["anomaly"] else "No",
                    fg('red') if r["confirmed"] else fg('green'),
                    "Yes" if r["confirmed"] else "No",
                    attr(0),
                    ",".join(ips)
                    )
            )
        print("")

