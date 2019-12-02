#!/usr/bin/env python3
import argparse
import os
import sys
import requests


def search(key, query):
    """
    Search in Koodous
    """
    url = "https://api.koodous.com/apks"
    headers = {"Authorization":"Token {}".format(key)}
    params = {'search':query}
    results = []
    finished = False
    next = None
    while not finished:
        if next:
            r = requests.get(url=next, headers=headers)
        else:
            r = requests.get(url=url, headers=headers, params=params)
        if r.status_code != 200:
            return results
        data = r.json()
        results += data['results']
        if data.get('next', None):
            next = data['next']
        else:
            finished = True
    return results


"""
Query a list of apps on Koodous, downvote and comment on all of them
"""
if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("QUERY", help="Query to be done on Koodous")
    args = parser.parse_args()

    koodous_conf = os.path.expanduser("~/.koodous")
    if not os.path.isfile(koodous_conf):
        print("Please add your Koodous key to ~/.koodous")
        sys.exit(-1)

    with open(koodous_conf, 'r') as f:
        key = f.read().strip()

    apks = search(key, args.QUERY)
    for app in apks:
        print(app['sha256'])
