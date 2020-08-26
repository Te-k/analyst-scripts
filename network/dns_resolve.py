import os
import argparse
from dns import resolver, reversename, exception


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Resolve domains')
    parser.add_argument('TXTFILE', help='Text files with domains')
    parser.add_argument('--verbose', '-v', action='store_true',
            help='verbose mode')
    args = parser.parse_args()

    results = {}

    with open(args.TXTFILE) as f:
        data = f.read().split("\n")

    for d in data:
        dd = d.strip()
        if dd not in results and len(dd) > 0:
            try:
                res = resolver.query(dd, "A")
            except (resolver.NoAnswer, resolver.NXDOMAIN):
                results[dd] = [True, ""]
                if args.verbose:
                    print("{}: NXDOMAIN".format(dd))
            except resolver.NoNameservers:
                results[dd] = [False, "SERVFAIL"]
                if args.verbose:
                    print("{}: SERVFAIL".format(dd))
            except exception.Timeout:
                results[dd] = [False, "Timeout"]
                if args.verbose:
                    print("{}: Timeout".format(dd))
            else:
                addr = [r.address for r in res]
                results[dd] = [True, addr]
                if args.verbose:
                    print("{}: {}".format(dd, addr))
    with open("resolutions.csv", "w+") as f:
        f.write("Domain,Success,Resolution\n")
        for domain in results.keys():
            f.write("{},{},{}\n".format(
                domain,
                results[domain][0],
                ";".join(results[domain][1])
            ))

    print("Results written in resolutions.csv")




