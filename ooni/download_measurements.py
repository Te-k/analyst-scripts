#!/usr/bin/env python3
import requests
import argparse
import os
import sys

OONI_API_BASE_URL = 'https://api.ooni.io/api/v1/'
MEASUREMENTS_PER_PAGE = 100000
TESTS = ["web_connectivity", "http_requests", "dns_consistency", "http_invalid_request_line", "bridge_reachability", "tcp_connect", "http_header_field_manipulation", "http_host", "multi_protocol_traceroute", "meek_fronted_requests_test", "whatsapp", "vanilla_tor", "facebook_messenger", "ndt", "dash", "telegram"]


def list_measurements(params, limit=10000, offset=100):
    """
    Query a list of measurements
    """
    res = []
    finished = False
    params["offset"] = offset
    params["limit"] = 100
    while not finished:
        r = requests.get(
            OONI_API_BASE_URL+'measurements',
            params=params
        )
        rr = r.json()
        if len(rr["results"]) == 0:
            finished = True
        else:
            res.extend(rr["results"])
            params["offset"] += offset
    return res


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Download some OONI measurements')
    parser.add_argument('--input', '-i', help="The input (for example a URL or IP address) to search measurements for")
    parser.add_argument('--test', '-t', help="Type of test")
    parser.add_argument('--country', '-c', help="Country code")
    parser.add_argument('--output', '-o', help="Output folder")
    parser.add_argument('--since', '-s', help='The start date of when measurements were run (ex. "2016-10-20T10:30:00")')
    parser.add_argument('--until', '-u', help='The end date of when measurement were run (ex. "2016-10-20T10:30:00")')
    parser.add_argument('--verbose', '-v', action='store_true',
            help="Verbose mode")
    parser.add_argument('--limit', '-l', default=10000, type=int,
            help="Maximum number of files downloaded")
    args = parser.parse_args()

    if args.output:
        if not os.path.isdir(args.output):
            print("Invalid folder")
            sys.exit(-1)
    else:
        args.output = "."

    # check that something is queried
    query = {}
    if args.input:
        query["input"] = args.input
    if args.country:
        query["probe_cc"] = args.country
    if args.test:
        if args.test not in TESTS:
            print("Invalid test name")
            sys.exit(-1)
        query["test_name"] = args.test

    if args.since:
        query["since"] = args.since

    res = list_measurements(query)
    if len(res) == args.limit:
        print("{} files identified, there are likely more files".format(len(res)))
    else:
        print("{} files identified".format(len(res)))

    for f in res:
        r = requests.get(f["measurement_url"])
        with open(os.path.join(args.output, f["measurement_id"]+ ".json"),"w") as fout:
            fout.write(r.text)
        print("Downloaded {}".format(f["measurement_id"] + ".json"))
    print("")
    print("{} files downloaded in {}".format(len(res), args.output))
