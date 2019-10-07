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
        print(app['sha256'])
