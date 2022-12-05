#!/usr/bin/env python2
# -*- coding: utf-8 -*-
import os
import argparse
import json
import requests


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Diff two IPs in Censys')
    parser.add_argument('IP1', help='IP1')
    parser.add_argument('IP2', help='IP2')
    args = parser.parse_args()

    key = get_apikey()



