import requests
import argparse
import sys
from dateutil.parser import parse

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='List IP prefixes advertised by an AS with their last date of advertismeent')
    parser.add_argument('ASN', help="AS Number")
    args = parser.parse_args()

    try:
        asn = int(args.ASN)
    except ValueError:
        try:
            asn = int(args.ASN[2:])
        except ValueError:
            print("Invalid AS number")
            sys.exit(-1)

    r = requests.get("https://stat.ripe.net/data/routing-history/data.json?min_peers=0&resource=AS{}".format(asn))
    if r.status_code != 200:
        print("Request failed : HTTP {}".format(r.status_code))
        sys.exit(-1)

    data = r.json()

    last_route = None

    for prefix in data["data"]['by_origin'][0]['prefixes']:
        print(prefix["prefix"] + " - " + prefix["timelines"][-1]["endtime"])
        dd = parse(prefix["timelines"][-1]["endtime"])
        if last_route is None:
            last_route = dd
        else:
            if dd > last_route:
                last_route = dd

    print("")
    print("Last route advertised: {}".format(last_route))
