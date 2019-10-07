#!/usr/bin/env python3
import ConfigParser
import os

def get_apikey():
    """Parse configuration file, returns a list of servers"""
    config = ConfigParser.ConfigParser()
    config.read(os.path.join(os.path.expanduser("~"), ".censys"))
    return (config.get('Censys', 'id'), config.get('Censys', 'secret'))
