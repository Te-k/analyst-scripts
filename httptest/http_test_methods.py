#! /usr/bin/env python2
import argparse
import os
import socket
from urlparse import urlparse
import re
import httplib

def send_request(method, host, path):
    conn = httplib.HTTPConnection(host)
    conn.request(method, path)
    return conn.getresponse()

def print_response(res):
    print "HTTP/1.1 %i %s" % (res.status, res.reason)
    for header in res.getheaders():
        print "%s: %s" % (header[0].capitalize(), header[1])
    print ""


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Identify the options supported by the web server')
    parser.add_argument('-t', '--test', help='Tests all the methods', action='store_true')
    parser.add_argument('-v', '--verbose', help='verbose mode', action="count", default=0)
    parser.add_argument('host', metavar='HOST',  help='Host targeted')
    args = parser.parse_args()

    # valid the host
    hosturl = urlparse(args.host)
    if hosturl.netloc == '':
        host = hosturl.path
    else:
        host = hosturl.netloc


    if args.test:
        print "Testing all HTTP methods"
        for method in ["GET", "OPTIONS", "HEAD", "POST", "PUT", "DELETE", "TRACE", "CONNECT"]:
            res =send_request(method, host, "/")
            if args.verbose > 0:
                print "%s /" % method
                print_response(res)
                #print "%s : %i %s" % (method, res.status, res.reason)
                #print "%s\n" % repr(res.getheaders())
            else:
                if res.status == 404 or res.status == 400 or res.status == 405:
                    print "%s: BLOCKED" % method
                else:
                    print "%s: AUTHORIZED" % method
    else:
        res = send_request("OPTIONS", host, "/")
        if res.getheader('allow'):
            print "Methods allowed: %s" % res.getheader('allow')
        else:
            print "No response from the server to OPTIONS method"







