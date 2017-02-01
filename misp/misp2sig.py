#!/usr/bin/env python2
# -*- coding: utf-8 -*-
import argparse
import sys
import ConfigParser
import urllib
from collections import Counter
from misp import MispServer, MispEvent
from misplib import parse_config

"""Tool to create signatures from MISP events
Author : Tek <tek@randhome.io>
Date : 01/02/2017
"""

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Command line interface to MISP servers')
    parser.add_argument('--server', '-s',  help='Server used for the request', required=True)
    parser.add_argument('--event', '-e',  help='Event infos', type=int, required=True)
    parser.add_argument('--dst', '-d',  choices=['gmailsearch'], required=True,
            help='Search for attributes of this type')
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

    if args.dst == "gmailsearch":
        event = server.events.get(args.event)
        attributes = filter(
            lambda x:x.type in ['domain', 'email-src', 'email-subject'] and x.to_ids,
            event.attributes
        )
        sig = " OR ".join(map(lambda x: '”' + x.value + '”', attributes))
        print(sig)
        print("\n")
        print("https://mail.google.com/mail/u/0/#search/" + urllib.quote(sig))

