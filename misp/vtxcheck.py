#!/usr/bin/env python2
# -*- coding: utf-8 -*-
import argparse
import os
import sys
import ConfigParser
from collections import Counter
from misp import MispServer, MispEvent, MispAttribute
from virus_total_apis import PublicApi as VirusTotalPublicApi
from virus_total_apis import PrivateApi as VirusTotalPrivateApi

"""VirusTotal Cross Checking for Misp server
Author : Tek <tek@randhome.io>
Date : 21/11/2016
Require virustotal-api (pip install virustotal-api)
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

def get_vt_key():
    """Get VirusTotal API key from .vtapi"""
    config = ConfigParser.ConfigParser()
    config.read(os.path.join(os.path.expanduser("~"), ".vtapi"))
    return [config.get('vt', 'type'), config.get('vt', 'apikey')]


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Command line interface to MISP servers')
    parser.add_argument('--server', '-s',  help='Server used for the request')
    parser.add_argument('--event', '-e',  help='Event infos', type=int)
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

    # Get VT api key from ~/.vtapi
    vtkey = get_vt_key()
    if vtkey[0] == "public":
        vtapi = VirusTotalPublicApi(vtkey[1])
    else:
        vtapi = VirusTotalPrivateApi(vtkey[1])
    event = server.events.get(args.event)

    types = ['md5', 'sha1', 'sha256']

    hashs = map(lambda x:x.value, filter(lambda x:x.type in types, event.attributes))
    # Ugly
    attributes = list(event.attributes._attributes)

    for attr in attributes:
        if attr.type in types:
            report =  vtapi.get_file_report(attr.value)
            if report['response_code'] == 200 and report['results']['response_code'] == 1:
                if args.verbose > 0:
                    print('%s hash found on VT' % attr.value)
                # File found
                for h in ['md5', 'sha1', 'sha256']:
                    if report['results'][h] not in hashs:
                        new_attr = MispAttribute()
                        new_attr.value = report['results'][h]
                        new_attr.category = attr.category
                        new_attr.to_ids = attr.to_ids
                        new_attr.type = h
                        new_attr.comment = attr.comment + " - XChecked via %s" % attr.value
                        new_attr.distribution = attr.distribution
                        event.attributes.add(new_attr)
                        server.events.update(event)
                        print("-> Added %s xchecked via %s" % (report['results'][h], attr.value))
                    else:
                        if args.verbose > 1:
                            print("Hash %s already in the event" % report['results'][h])
            else:
                if args.verbose > 0:
                    print('%s hash not found on VT' % attr.value)








