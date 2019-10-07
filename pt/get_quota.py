#!/usr/bin/env python3
import requests
import os
import sys
import json

if __name__ == '__main__':
    conf_file = os.path.join(os.path.expanduser("~"), ".config/passivetotal/api_config.json")
    if os.path.isfile(conf_file):
        with open(conf_file, 'r') as f:
            conf = json.loads(f.read())
    else:
        print('No config file')
        sys.exit(1)

    auth = (conf['username'], conf['api_key'])
    r = requests.get('https://api.passivetotal.org/v2/account/quota', auth=auth)
    print(json.dumps(r.json(), indent=4, sort_keys=True))
