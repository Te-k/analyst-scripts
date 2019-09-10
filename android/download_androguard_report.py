#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
Copyright (c) 2015. The Koodous Authors. All Rights Reserved.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

import requests
import argparse
import json
import os

__author__ = 'A.Sánchez <asanchez@koodous.com> && xgusix'


def download_report(sha256, dst, key):
    """
        Function to download and save the Androguard report from Koodous.
    """

    url = 'https://api.koodous.com/apks/{}/analysis'.format(sha256)
    headers = {"Authorization":"Token {}".format(key)}
    data = dict()
    response = requests.get(url=url, headers=headers)

    #Check if the APK is in the database
    if response.status_code == 405:
        print ("Sorry, this APK does not have a report yet, you can request it "
            "via the Koodous website.")
    elif response.status_code == 404:
        print ("Sorry, we don\'t have this APK in Koodous. You can share with "
            "the community through our website.")

    rt = False

    if response.status_code == 200:
        rt = True
        data = response.json()
        try:
            json.dump(data.get('androguard', None), open(dst, 'w'))
            print("Report created in {}".format(dst))
        except Exception as e:
            print("There was an error writing the report: {}".format(e))
            rt = False

    return rt


def main():
    parser = argparse.ArgumentParser(
                description="Tool to download reports from Koodous")
    parser.add_argument('-s', '--sha256', action='store',
                dest='sha256')
    parser.add_argument('-o', '--output', action='store', dest='filename',
                help=("File to dump the downloaded report, by default: "
                "<sha256>-report.json"))

    args = parser.parse_args()

    koodous_conf = os.path.expanduser("~/.koodous")
    if not os.path.isfile(koodous_conf):
        print("Please add your Koodous key to ~/.koodous")
        sys.exit(-1)

    with open(koodous_conf, 'r') as f:
        key = f.read().strip()


    if not args.sha256:
        print("I need at least a SHA256 hash!")
        parser.print_help()
        return

    report_name = "{}-report.json".format(args.sha256)
    if args.filename:
        report_name = args.filename

    success = download_report(sha256=args.sha256, dst=report_name, key=key)
    if success:
        print("Androguard report saved in {}".format(report_name))


if __name__ == '__main__':
    main()
