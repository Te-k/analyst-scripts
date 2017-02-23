#!/usr/bin/env python2
import httplib
import argparse
import urlparse
import random
import urllib2

def is_blocked(res):
    if res.status == 403:
        return True
    else:
        return False

def send_request(host, req, get="GET", display=False):
    conn = httplib.HTTPConnection(host)
    conn.request(get, req)
    res =  conn.getresponse()
    if display:
        print "Request: %s" % (get+ " " + host+req)+"\t/\t",
        print "Response: %i" % res.status
    return is_blocked(res)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Test if common sqli keywords are blocked by the site')
    parser.add_argument('-f', '--file', help='File which contain the list of common files (default is fun_files.txt', default='sqli_keywords.txt')
    parser.add_argument('-v', '--verbose', help='verbose mode', action="count", default=0)
    parser.add_argument('-r', '--random', help='If the keyword is blocked test with random uppercase', action="store_true")
    parser.add_argument('host', metavar='HOST',  help='Host targeted')

    args = parser.parse_args()

    if not args.host.startswith("http"):
        host = urlparse.urlparse("http://" + args.host)
    else:
        host = urlparse.urlparse(args.host)
    req = urllib2.Request(host.geturl())
    try:
        r = urllib2.urlopen(req)
        if r.getcode() != 200:
            print "Host unavailable!"
            exit(1)
    except urllib2.URLError as e:
        print "Host unavailable!"
        exit(1)

    fl = open(args.file, "r")
    kw = fl.readline().strip()
    while kw != "":
        if send_request(host.netloc, host.path+"?"+host.query+'+'+kw, display=(args.verbose > 1)):
            if args.random:
                kw2 = "".join( random.choice([k.upper(), k ]) for k in kw.lower() )
                if send_request(host.netloc, host.path+"?"+host.query+'+'+kw2, display=(args.verbose>1)):
                    print "BLOCKED: %s (even with randomized char)" % kw
                else:
                    print "BLOCKED: %s (but PASS with %s)" % (kw, kw2)
            else:
                print "BLOCKED: %s" % kw
        else:
            if args.verbose > 0:
                print "PASS: %s" % kw
        kw = fl.readline().strip()
