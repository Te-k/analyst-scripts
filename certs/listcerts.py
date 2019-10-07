#!/usr/bin/env python3
import argparse
import operator
from pycrtsh import Crtsh
from collections import Counter

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='List certificates for a domain')
    parser.add_argument('DOMAIN', help='an integer for the accumulator')
    args = parser.parse_args()

    crt = Crtsh()
    index = crt.search(args.DOMAIN)
    domains = []
    print("Certificates")
    for c in index:
        data = crt.get(c["id"], type="id")
        print("%s\t%s\t%s\t%s" % (
                data["subject"]["commonName"],
                data["not_before"].isoformat(),
                data["not_after"].isoformat(),
                data["sha1"]
            )
        )
        if "alternative_names" in data["extensions"]:
            domains += list(set([a[2:] if a.startswith("*.") else a for a in data["extensions"]["alternative_names"]]))

    print("\nDomains")
    count = Counter(domains)
    for d in sorted(count.items(), key=operator.itemgetter(1), reverse=True):
        print("-%s: %i occurences" % (d[0], d[1]))
