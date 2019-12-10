#! /usr/bin/env python
import json
import argparse
import requests


class UrlScan(object):
    def __init__(self):
        self.url = "https://urlscan.io/api/v1/"

    def search(self, query, size=100, offset=0):
        params = {
            'q': query,
            'size': size,
            'offset': offset
        }
        r = requests.get(self.url + "search/", params=params)
        return r.json()

    def view(self, uid):
        r = requests.get(self.url + 'result/' + uid)
        return r.json()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Query urlscan')
    subparsers = parser.add_subparsers(help='Subcommand')
    parser_a = subparsers.add_parser('search', help='Search in urlscan')
    parser_a.add_argument('QUERY', help='DOMAIN to be queried')
    parser_a.add_argument('--raw', '-r', action='store_true', help='Shows raw results')
    parser_a.set_defaults(subcommand='search')
    parser_c = subparsers.add_parser('view', help='View urlscan analysis')
    parser_c.add_argument('UID', help='UId of the analysis')
    parser_c.set_defaults(subcommand='view')
    args = parser.parse_args()

    if 'subcommand' in args:
        us = UrlScan()
        if args.subcommand == 'search':
            # Search
            res = us.search(args.QUERY)
            if args.raw:
                print(json.dumps(res, sort_keys=True, indent=4))
            else:
                if len(res['results']) > 0:
                    for r in res['results']:
                        print("{} - {} - {} - https://urlscan.io/result/{}".format(
                            r["task"]["time"],
                            r["page"]["url"],
                            r["page"]["ip"],
                            r["_id"]
                            )
                        )
                else:
                    print("No results for this query")
        elif args.subcommand == 'view':
            print(json.dumps(us.view(args.UID), sort_keys=True, indent=4))
        else:
            parser.print_help()
    else:
        parser.print_help()
