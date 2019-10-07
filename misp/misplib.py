#!/usr/bin/env python3
try:
    import ConfigParser
except ImportError:
    # Python 3
    import configparser as ConfigParser
import os

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
