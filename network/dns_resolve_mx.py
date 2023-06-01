import os
import argparse
from dns import resolver, reversename, exception
from IPy import IP

def is_ip(target):
    """
    Test if a string is an IP address
    """
    if isinstance(target, str):
        try:
            IP(target)
            return True
        except ValueError:
            return False
    else:
        return False


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
                res = resolver.resolve(dd, "MX")
            except (resolver.NoAnswer, resolver.NXDOMAIN):
                results[dd] = [True, "", ""]
                if args.verbose:
                    print("{}: NXDOMAIN".format(dd))
            except resolver.NoNameservers:
                results[dd] = [False, "SERVFAIL", ""]
                if args.verbose:
                    print("{}: SERVFAIL".format(dd))
            except exception.Timeout:
                results[dd] = [False, "Timeout", ""]
                if args.verbose:
                    print("{}: Timeout".format(dd))
            else:
                for rdata in res:
                    if is_ip(rdata.exchange.to_text()):
                        # IP directly
                        results[dd] = [True, "", rdata.exchange.to_text()]
                        if args.verbose:
                            print("{}: {}".format(dd, rdata.exchange.to_text()))
                    else:
                        # Domain
                        try:
                            ip = [b.address for b in resolver.resolve(rdata.exchange, 'A')][0]
                        except (resolver.NoAnswer, resolver.NXDOMAIN):
                            # Hostname without IPv4
                            results[dd] = [True, rdata.exchange.to_text(), ""]
                            if args.verbose:
                                print("{}: {}".format(dd, rdata.exchange.to_text()))
                        else:
                            results[dd] = [True, rdata.exchange.to_text(), ip]
                            if args.verbose:
                                print("{}: {} - {}".format(dd, rdata.exchange.to_text(), ip))
    with open("resolutions.csv", "w+") as f:
        f.write("Domain,Success,Domain,IP\n")
        for domain in results.keys():
            f.write("{},{},{},{}\n".format(
                domain,
                results[domain][0],
                results[domain][1],
                results[domain][2]
            ))

    print("Results written in resolutions.csv")




