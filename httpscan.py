#!/usr/bin/env python2
# -*- coding: utf-8 -*-
import requests
import argparse
from urlparse import urljoin

USERAGENT = "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1"


def scan(server, path):
    headers = {'user-agent': USERAGENT}
    if not server.startswith("http://"):
        server = "http://" + server
    return requests.get(urljoin(server, path), headers=headers, timeout=0.5)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Scan HTTP server check for a file')
    parser.add_argument('PATH', help='a weird PNG file')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--server', '-s', help="Server to check")
    group.add_argument('--file', '-f', help="File containing list of IP/domains")
    parser.add_argument('--verbose', '-v', action='store_true', help='Be verbose')
    args = parser.parse_args()

    if args.server is not None:
        try:
            res = scan(args.server, args.PATH)
            print("Result code: %i" % res.status_code)
            if args.verbose:
                print(res.text)
        except requests.exceptions.ConnectionError:
            print("Connection Error")
        except requests.exceptions.ReadTimeout:
            print("Connection Timeout")
        except requests.exceptions.TooManyRedirects:
            print("Too many redirects")

    elif args.file is not None:
        f = open(args.file, "r")
        servers = f.read().split("\n")
        servers = filter(lambda x: x != '', map(lambda x:x.strip(), servers))
        f.close()

        for server in servers:
            try:
                res = scan(server, args.PATH)
                print("%s -> %i" % (server, res.status_code))
            except requests.exceptions.ConnectionError:
                print("%s -> Connection Error" % server)
            except requests.exceptions.ReadTimeout:
                print("%s -> Connection timeout" % server)
            except requests.exceptions.TooManyRedirects:
                print("%s -> Too many redirects" % server)
