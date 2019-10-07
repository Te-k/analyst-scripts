#!/usr/bin/env python3
import requests
import os
import sys
import json
import argparse


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Process some integers.')
    parser.add_argument('PROJECT', help='Passive Total project')
    args = parser.parse_args()

    conf_file = os.path.join(os.path.expanduser("~"), ".config/passivetotal/api_config.json")
    if os.path.isfile(conf_file):
        with open(conf_file, 'r') as f:
            conf = json.loads(f.read())
    else:
        print('No config file')
        sys.exit(1)

    auth = (conf['username'], conf['api_key'])
    r = requests.get('https://api.passivetotal.org/v2/artifact',
            params={'project': args.PROJECT}, auth=auth)
    for a in r.json()['artifacts']:
        print(a['query'])
