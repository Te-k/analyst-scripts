#!/usr/bin/env python2
# -*- coding: utf-8 -*-
import censys.query
import argparse
import os
import json
import time
from censyslib import *

def get_ipv4records(censys):
    series = cc.get_series_details("ipv4")
    return sorted(series["tables"])[::-1]


if __name__ == '__main__':
    key = get_apikey()

    cc = censys.query.CensysQuery(api_id=key[0], api_secret=key[1])

    series = get_ipv4records(cc)
    for ip in series:
        print(ip)

