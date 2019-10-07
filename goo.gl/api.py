#!/usr/bin/env python3
import argparse
import json
import requests
import os
import sys
try:
    import configparser as cp
except ImportError:
    # python2
    import ConfigParser as cp


class GoogleShortener(object):
    def __init__(self, config):
        self.host = 'https://www.googleapis.com/urlshortener/v1/url'
        self.token = config["key"]

    def get_analytics(self, hash):
        params = {'key': self.token, 'shortUrl': 'http://goo.gl/' + hash, 'projection': 'FULL'}
        r = requests.get(self.host, params=params)
        return r.json()

    def expand(self, hash):
        params = {'key': self.token, 'shortUrl': 'http://goo.gl/' + hash}
        r = requests.get(self.host, params=params)
        return r.json()

    def shorten(self, long_url):
        params = {'key': self.token, 'longUrl': long_url}
        r = requests.post(self.host, data=params)
        return r.json()


def load_config():
    config = cp.ConfigParser()
    if os.path.isfile(os.path.join(os.path.expanduser("~"), ".goo.gl")):
        conffile = os.path.join(os.path.expanduser("~"), ".goo.gl")
    else:
        print("Couldn't find the config file")
        sys.exit(1)
    config.read(conffile)
    return {"key": config.get("API", "key")}

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Check goo.gl infos through the API')
    parser.add_argument('--hash', '-H', help='HASH of a link')
    parser.add_argument('--file', '-f', help='Get hashes from a file')
    args = parser.parse_args()

    config = load_config()
    go = GoogleShortener(config)
    if args.hash:
        print(json.dumps(go.get_analytics(args.hash), sort_keys=True, indent=4, separators=(',', ':')))
    elif args.file:
        f = open(args.file, 'r')
        data = f.read().split()
        f.close()
        print("Date;Short URL;Long URL;Analytics;Short URL Clicks;Long URL Clicks")
        for d in data:
            res = go.get_analytics(d.strip())
            print("%s;%s;%s;https://goo.gl/#analytics/goo.gl/%s/all_time;%s;%s" %
                    (
                        res["created"],
                        res["id"],
                        res["longUrl"],
                        res["id"][-6:],
                        res["analytics"]["allTime"]["shortUrlClicks"],
                        res["analytics"]["allTime"]["longUrlClicks"]
                    )
            )
    else:
        print("Please provide either a hash or a file")
        parser.print_help()
