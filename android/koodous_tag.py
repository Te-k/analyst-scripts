#!/usr/bin/env python3
import argparse
import os
import sys
import requests


class Koodous(object):
    def __init__(self, key):
        self.key = key
        self.url = "https://api.koodous.com/"
        self.headers = headers = {"Authorization":"Token {}".format(key)}

    def search(self, query):
        """
        Search in Koodous
        """
        url = self.url + "apks"
        params = {'search':query}
        results = []
        finished = False
        next = None
        while not finished:
            if next:
                r = requests.get(url=next, headers=self.headers)
            else:
                r = requests.get(url=url, headers=self.headers, params=params)
            if r.status_code != 200:
                return results
            data = r.json()
            results += data['results']
            if data.get('next', None):
                next = data['next']
            else:
                finished = True
        return results

    def downvote(self, sha256):
        """
        Downvote a sample
        """

        url = '%sapks/%s/votes' % (self.url, sha256)
        res = requests.post(url, data={'kind': 'negative'}, headers=self.headers)
        return res.json()

    def comment(self, sha256, text):
        url = url = '%sapks/%s/comments' % (self.url, sha256)
        payload = {'text': text}
        response = requests.post(url=url, headers=self.headers, data=payload)
        return response.json()

"""
Query a list of apps on Koodous, downvote and comment on all of them
"""
if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("QUERY", help="Query to be done on Koodous")
    parser.add_argument("--comment", "-c", help="Comment to be added to the samples")
    parser.add_argument("--negative", "-n",
            help="Vite negative", action="store_true")
    args = parser.parse_args()

    koodous_conf = os.path.expanduser("~/.koodous")
    if not os.path.isfile(koodous_conf):
        print("Please add your Koodous key to ~/.koodous")
        sys.exit(-1)

    with open(koodous_conf, 'r') as f:
        key = f.read().strip()

    koodous_obj = Koodous(key)
    apks = koodous_obj.search(args.QUERY)
    for app in apks:
        if args.comment:
            koodous_obj.comment(app['sha256'], args.comment)
        if args.negative:
            koodous_obj.downvote(app['sha256'])
        print(app['sha256'])
