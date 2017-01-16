#!/usr/bin/env python2
# -*- coding: utf-8 -*-
import argparse
import sys
from collections import Counter
from misp import MispServer, MispEvent, MispTransportError, MispAttribute
from misplib import parse_config

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Search for MISP attributes in another MISP instance')
    parser.add_argument('SERVER_SOURCE',  help='Server having the IOCs')
    parser.add_argument('EVENT_SOURCE', help='Event having new IOCs', type=int)
    parser.add_argument('SERVER_DEST', help='Server for the research')
    parser.add_argument('-v', '--verbose', action='count', default=0)
    args = parser.parse_args()

    config = parse_config()

    if args.SERVER_SOURCE.lower() not in config.keys():
        print("Unknown source server, quitting...")
        sys.exit(1)
    else:
        source_server = MispServer(url=config[args.SERVER_SOURCE.lower()]['url'],
                    apikey=config[args.SERVER_SOURCE.lower()]['key'],
                    ssl_chain=False)

    if args.SERVER_DEST.lower() not in config.keys():
        print("Unknown destination server, quitting...")
        sys.exit(1)
    else:
        dest_server = MispServer(url=config[args.SERVER_DEST.lower()]['url'],
                    apikey=config[args.SERVER_DEST.lower()]['key'],
                    ssl_chain=False)

    try:
        source_event = source_server.events.get(args.EVENT_SOURCE)
    except MispTransportError:
        print("Impossible to find the event source, quitting")
        sys.exit(1)

    for attr in source_event.attributes:
        if attr.category != 'Internal reference':
            res = dest_server.attributes.search(value=attr.value)
            if len(res) == 0:
                if args.verbose > 0:
                    print("Attr %s: no results" % attr.value)
            else:
                print("Attr %s, result founds" % attr.value)
                for event in res:
                    print("\t-> %i - %s" % (event.id, event.info))
