#!/usr/bin/env python3
import argparse
import os
import sys
try:
    import koodous
except ModuleNotFoundError:
    print("Please install koodous python library - pip install koodous")
    sys.exit(-1)


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

    koodous_obj = koodous.Koodous(key)
    apks = koodous_obj.search(args.QUERY)
    for app in apks:
        if args.comment:
            koodous_obj.post_comment(app['sha256'], args.comment)
        if args.negative:
            koodous_obj.vote_apk(app['sha256'], koodous.NEGATIVE)
        print(app['sha256'])
