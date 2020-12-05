import argparse
import os
import sys


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Check if domains are in the Umbrealla top 1million list')
    parser.add_argument('DOMAINLIST', help='List of domains')
    parser.add_argument('UMBRELLALIST', help='Cisco Umbrella top 1million list')
    args = parser.parse_args()

    umbrella = {}
    with open(args.UMBRELLALIST) as f:
        for l in f.read().split('\n'):
            if l.strip() == '':
                continue
            ll = l.strip().split(',')
            umbrella[ll[1]] = ll[0]

    with open(args.DOMAINLIST) as f:
        data = f.read().split('\n')
    data.remove('')

    for d in data:
        if d.strip() == "":
            continue
        if d.strip() in umbrella.keys():
            print("{} in the umbrella list at {} position".format(
                d.strip(),
                umbrella[d.strip()]
            ))
