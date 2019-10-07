#!/usr/bin/env python3
import argparse


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Convert puny code domains')
    parser.add_argument('DOMAIN', help='DOMAIN to be converted')
    args = parser.parse_args()

    if args.DOMAIN.startswith("xn--"):
        print(args.DOMAIN.decode('idna'))
    else:
        print(args.DOMAIN.decode('utf-8').encode('idna'))
