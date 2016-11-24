#!/usr/bin/env python2
# -*- coding: utf-8 -*-
import argparse
import os
import sys
import ConfigParser
from collections import Counter
from misp import MispServer, MispEvent, MispTransportError, MispAttribute

"""Command line interface for misp servers
Author : Tek <tek@randhome.io>
Date : 21/11/2016
"""

def parse_config():
    """Parse configuration file, returns a list of servers"""
    config = ConfigParser.ConfigParser()
    config.read(os.path.join(os.path.expanduser("~"), ".misp"))
    servers = {}
    for s in config.sections():
        try:
            info = {
                    'url': config.get(s, 'url'),
                    'key': config.get(s, 'key')
            }
            servers[s.lower()] = info
            if config.get(s, 'default').lower() == 'true':
                servers['default'] = info
        except ConfigParser.NoOptionError:
            pass

    return servers


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Command line interface to MISP servers')
    parser.add_argument('SERVER_SOURCE',  help='Server source for the copy')
    parser.add_argument('EVENT_SOURCE', help='Event source', type=int)
    parser.add_argument('SERVER_DEST', help='Server destination')
    parser.add_argument('EVENT_DEST', type=int,  help='Event destination')
    parser.add_argument('--no-cleaning', '-c', action='store_true', help='Do not clean attributes (personal rules)')
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


    try:
        dest_event = dest_server.events.get(args.EVENT_DEST)
    except MispTransportError:
        print("Impossible to find the event destination, quitting")
        sys.exit(1)

    for attr in source_event.attributes:
        new_attr = MispAttribute()
        new_attr.value = attr.value
        new_attr.category = attr.category
        new_attr.to_ids = attr.to_ids
	if args.no_cleaning is False:
	    if attr.type == "hostname":
		new_attr.type = "domain"
	    elif attr.type == "ip-src":
		new_attr.type = "ip-dst"
	    else:
		new_attr.type = attr.type
	    if "Imported via" in str(attr.comment):
		new_attr.comment = ""
	    else:
		new_attr.comment = attr.comment
            new_attr.distribution = 5
        else:
            new_attr.comment = attr.comment
            new_attr.type = attr.type
            new_attr.distribution = attr.distribution

        dest_event.attributes.add(new_attr)
        try:
            dest_server.events.update(dest_event)
        except requests.exceptions.ConnectionError:
            print("Failed connection")
        except MispTransportError:
            print("Failed connection")
        print("Uploaded %s / %s / %s" % (attr.type, attr.category, attr.value))
