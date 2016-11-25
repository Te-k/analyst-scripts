#!/usr/bin/env python2
# -*- coding: utf-8 -*-
import argparse
import os
import sys
import ConfigParser
from collections import Counter
from misp import MispServer, MispEvent

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
    parser.add_argument('--list', '-l', action='store_true', help='List events')
    parser.add_argument('--server', '-s',  help='Server used for the request')
    parser.add_argument('--event', '-e',  help='Event infos', type=int)
    parser.add_argument('--attr', '-a',  help='Search for this attribute')
    parser.add_argument('--type', '-t',  help='Search for attributes of this type')
    parser.add_argument('--no-ids', help='Disable IDS for these attributes', action='store_true')
    parser.add_argument('--to-ids', help='Enable IDS for these attributes', action='store_true')
    parser.add_argument('--detection', help='Summarize IOCs for detection', action='store_true')
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

    if args.list:
        # List events
        events = server.events.list(0)
        for event in sorted(events, key=lambda x:x.id):
            print("%i : %s" % (event.id, event.info))
    elif args.event is not None:
        event = server.events.get(args.event)
        if args.attr is None and args.type is None and args.detection is None:
            print("Event %i : %s" % (event.id, event.info))
            print("Tags : %s" % ", ".join(map(lambda x:str(x.name), event.tags)))
            print("%i Attributes including:" % len(event.attributes))
            attrs = Counter(map(lambda x:x.type, event.attributes))
            attrs_ids = Counter(map(lambda x:x.type, filter(lambda x:x.to_ids, event.attributes)))
            for type in attrs:
                print("\t- %i %s (%i for detection)" % (attrs[type], type, attrs_ids[type]))
        else:
            if args.type is not None:
                # Display all attributes from this type
                for attr in event.attributes:
                    if attr.type == args.type:
                        if args.to_ids:
                            if attr.to_ids == 0:
                                attr.to_ids = 1
                                server.attributes.update(attr)
                                print("Updated attr %s for IDS detection" % attr.value)
                            else:
                                print("Attr %s already for IDS detection" % attr.value)
                        elif args.no_ids:
                            if attr.to_ids == 1:
                                attr.to_ids = 0
                                server.attributes.update(attr)
                                print("Updated attr %s not for IDS detection" % attr.value)
                            else:
                                print("Attr %s already not for IDS detection" % attr.value)
                        else:
                            print("%s\t%s\t%s\t%s\t%s" % (attr.category, attr.type, attr.value, attr.comment, attr.to_ids))
            elif args.attr is not None:
                # search by attribute value
                for attr in event.attributes:
                    if args.attr in str(attr.value):
                        if args.to_ids:
                            if attr.to_ids == 0:
                                attr.to_ids = 1
                                server.attributes.update(attr)
                                print("Updated attr %s for IDS detection" % attr.value)
                            else:
                                print("Attr %s already for IDS detection" % attr.value)
                        elif args.no_ids:
                            if attr.to_ids == 1:
                                attr.to_ids = 0
                                server.attributes.update(attr)
                                print("Updated attr %s not for IDS detection" % attr.value)
                            else:
                                print("Attr %s already not for IDS detection" % attr.value)
                        else:
                            print("%s\t%s\t%s\t%s\t%s" %
                                    (
                                        attr.category,
                                        attr.type,
                                        attr.value,
                                        attr.comment,
                                        attr.to_ids
                                    )
                            )
            else:
                # misp -e 42 --detection : give info on IOCs for detection
                print("Event %i : %s" % (event.id, event.info))
                tags = map(lambda x:str(x.name), event.tags)
                print("Tags : %s" % ", ".join(tags))
                if "DETECT" in tags:
                    print("Event enabled for detection")
                else:
                    print("Event not enabled for detection")
                print("%i Attributes including:" % len(event.attributes))
                attrs = Counter(map(lambda x:x.type, event.attributes))
                attrs_ids = Counter(map(lambda x:x.type, filter(lambda x:x.to_ids, event.attributes)))
                for type in attrs:
                    print("\t- %i %s for detection (%i total)" % (attrs_ids[type], type, attrs[type]))

                print("Total: %s attributes for detection" % sum(attrs_ids.values()))

    elif args.attr is not None:
            # Search attributes
            res = server.attributes.search(attr=args.attr)
            if len(res) == 0:
                print("Attribute not found")
            else:
                print("Attribute found in events:")
                for event in res:
                    print("%i : %s" % (event.id, event.info))

    elif args.detection:
        iocs = []
        events = server.events.list(0)
        for f_event in events:
            event = server.events.get(f_event.id)
            tags = map(lambda x:str(x.name), event.tags)
            if "DETECT" in tags:
                attrs_ids = filter(lambda x:x.to_ids, event.attributes)
                iocs += attrs_ids
                print("%i - %s : %i attributes for detection (%i total)" % (
                    event.id,
                    event.info,
                    len(attrs_ids),
                    len(event.attributes)
                    )
                )

        print("")
        print("%i IOCs for detection including:" % len(iocs))
        count = Counter(map(lambda x:x.type, iocs))
        for type in count:
            print("\t- %i %s indicator" % (count[type], type))


