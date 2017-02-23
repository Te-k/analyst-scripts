#! /usr/bin/env python2
import urllib2
import urlparse
import argparse
import os

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Check fun files on the web server')
    parser.add_argument('-f', '--file', help='File which contain the list of common files (default is fun_files.txt)', default='fun_files.txt')
    parser.add_argument('-n', '--no-save', help='Do not save file found', action='store_true')
    parser.add_argument('-o', '--outdir', help='Output directory (default is files)', default='files')
    parser.add_argument('-v', '--verbose', help='verbose mode', action="count", default=0)
    parser.add_argument('host', metavar='HOST',  help='Host targeted')
    args = parser.parse_args()

    if not args.host.startswith("http"):
        host = "http://" + args.host
        hostname = args.host
    else:
        host = args.host
        hostname = urlparse.urlparse(args.host).netloc

    # Check host validity
    req = urllib2.Request(host)
    try:
        r = urllib2.urlopen(req)
        if r.getcode() != 200:
            print "Host unavailable!"
            exit(1)
    except urllib2.URLError as e:
        print "Host unavailable!"
        exit(1)

    if not args.no_save:
        # Check dirs
        if not os.path.exists(args.outdir):
            os.makedirs(args.outdir)
        if not os.path.exists(args.outdir + "/" + hostname):
            os.makedirs(args.outdir + "/" + hostname)

    # Loop on the file
    ffile = open(args.file, "r")
    fname = ffile.readline().strip()
    found = False
    while fname != "":
        req = urllib2.Request(urlparse.urljoin(host, fname))
        try:
            resp = urllib2.urlopen(req)
            if resp.getcode() == 200:
                found = True
                print "%s found ! (%i -> saved)" % (fname, resp.getcode())
                if not args.no_save:
                    fout = open(args.outdir + "/" + hostname + "/" + fname, "a+")
                    fout.write(resp.read())
                    fout.close()
            else:
                print "%s found ! (%i)" % (fname, resp.getcode())
        except urllib2.HTTPError as e:
            if e.code != 404:
                print "%s found! (%i)" % (fname, e.code)
            else:
                if args.verbose > 0:
                    print "%s not available" % fname

        fname = ffile.readline().strip()

    if not found:
        print "No file found"
