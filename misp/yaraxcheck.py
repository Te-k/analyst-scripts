#!/usr/bin/env python2
# -*- coding: utf-8 -*-
import argparse
import sys
import yara
from misp import MispServer, MispEvent, MispAttribute
from misplib import parse_config

"""Checking yara rules from
Author : Tek <tek@randhome.io>
Date : 17/01/2017
Require yara python library, see https://github.com/VirusTotal/yara-python
"""

def check_yara(rules, data, name, verbose):
    res = rules.match(data=data)
    if len(res) > 0:
        print("%s: MATCH %s" % (
                name,
                ",".join(map(lambda x: x.rule, res))
            )
        )
    else:
        if verbose > 0:
            print('%s: no match' % name)

    return res


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Check yara rules on samples in MISP')
    parser.add_argument('--server', '-s',  help='Server used for the request')
    parser.add_argument('--event', '-e',  help='Event infos', type=int)
    parser.add_argument('--rules', '-r',  help='Yara rule file')
    parser.add_argument('-v', '--verbose', action='count', default=0)
    args = parser.parse_args()

    config = parse_config()
    if args.server is not None:
        if args.server.lower() in config.keys():
            server = MispServer(url=config[args.server.lower()]['url'],
                    apikey=config[args.server.lower()]['key'],
                    ssl_chain=False)
        else:
            print("Server not found, quitting...")
            sys.exit(1)

    else:
        if 'default' not in config.keys():
            print("No default severs in MISP conf, quitting...")
            sys.exit(1)
        else:
            server = MispServer(url=config['default']['url'],
                    apikey=config['default']['key'],
                    ssl_chain=False)

    event = server.events.get(args.event)
    rules = yara.compile(filepath=args.rules)

    for attr in event.attributes:
        if attr.type == 'malware-sample':
            # Ignore zip files
            value = str(attr.value)
            if "|" in value:
                fname = value.split("|")[0]
                if not fname.endswith(".zip"):
                    data = server.download(attr)
                    check_yara(rules, data, attr.value, args.verbose)
                else:
                    if args.verbose > 1:
                        print("%s not considered (.zip file)" % (attr.value))
            else:
                data = server.download(attr)
                check_yara(rules, data, attr.value, args.verbose)
        else:
            if args.verbose > 1:
                print("%s not considered (type %s)" % (attr.value, attr.type))
