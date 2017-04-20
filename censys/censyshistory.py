#!/usr/bin/env python2
# -*- coding: utf-8 -*-
import censys.query
import argparse
import os
import json
import time
from censyslib import *

PARAMS = [
    "p80.http.get.body",
    "p80.http.get.title",
    "p80.http.get.status_code",
    "p80.http.get.body_sha256",
    "p80.http.get.headers.server",
    "p80.http.get.headers.content_length",
    "p80.http.get.headers.last_modified",
    "p443.https.tls.certificate.parsed.subject_dn",
    "p443.https.tls.certificate.parsed.fingerprint_sha256",
    "p443.https.tls.certificate.parsed.issuer_dn"
]

def get_ipv4records(censys):
    series = cc.get_series_details("ipv4")
    return sorted(series["tables"])[::-1]


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Request historical information on an IP address from censys')
    parser.add_argument('IP', help='IPv4 address')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose mode')
    parser.add_argument('--limit', '-l', default=10, type=int, help='Number of table requested (starting from the more recent) ')
    parser.add_argument('--until', '-u', default=None, type=int, help='Date until request will be done (format like 20160101)')
    parser.add_argument('--delay', '-d', default=5, type=int, help='Delay in second between each request')
    args = parser.parse_args()

    key = get_apikey()

    cc = censys.query.CensysQuery(api_id=key[0], api_secret=key[1])

    series = get_ipv4records(cc)

    data = {}
    if args.until is not None:
        target = filter(lambda x: int(x.split(".")[1]) >= int(args.until), series)
    else:
        if args.limit == 0:
            target = series
        else:
            target = series[:args.limit]

    for serie in target:
        print("Requesting serie %s" % serie)

        request = cc.new_job("select %s from %s where ip = '%s'" % (",".join(PARAMS), serie, args.IP))
        if args.verbose:
            print("Request launched, waiting %i seconds" % args.delay)
        job_id = request["job_id"]
        done = False
        waited = False
        while not done:
            if waited:
                time.sleep(2)
            else:
                time.sleep(args.delay)
                waited = True
            status = cc.check_job_loop(job_id)
            done = (status['status'] == 'success')
            if args.verbose and not done:
                print("Request still pending, waiting")
        try:
            result = cc.get_results(job_id, page=1)
            if args.verbose:
                print(result)
            sdata = {}
            for i in range(len(PARAMS)):
                sdata[PARAMS[i]] = result['rows'][0]['f'][i]['v']
            data[serie] = sdata
            if args.verbose:
                print(sdata)
        except (IndexError, ValueError, KeyError):
            # Weird results, don't know why
            if args.verbose:
                print("Results in bad format, skipping these from the dump")

    fout = open("a.out", "w")
    fout.write(json.dumps(data))
    fout.close()
