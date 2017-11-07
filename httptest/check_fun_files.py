#! /usr/bin/env python2
try:
    import urlparse
except ImportError:
    # python 3
    import urllib.parse as urlparse
import argparse
import requests
import os

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Check fun files on the web server')
    parser.add_argument('-f', '--file', help='File which contain the list of common files (default is fun_files.txt)', default='fun_files.txt')
    parser.add_argument('-s', '--save', help='Save file found', action='store_true')
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

    headers = {
        "User-Agent": "Baiduspider+(+http://www.baidu.com/search/spider.htm)"
    }

    # Check host validity
    try:
        r = requests.get(host, headers=headers)
    except requests.ConnectionError:
        print("Host unavailable!")
        exit(1)
    if r.status_code != 200:
        print("Bad HTTP code when requesting / (%i), quitting" % r.status_code)
        exit(1)

    if args.save:
        # Check dirs
        if not os.path.exists(args.outdir):
            os.makedirs(args.outdir)
        if not os.path.exists(args.outdir + "/" + hostname):
            os.makedirs(args.outdir + "/" + hostname)


    # Loop on the file
    ffile = open(args.file, "r")
    fname = ffile.readline().strip()
    while fname != "":
        try:
            r = requests.get(urlparse.urljoin(host, fname), headers=headers)
            if r.status_code == 200:
                if args.save:
                    print("%s found ! (-> saved)" % fname)
                    fout = open(args.outdir + "/" + hostname + "/" + fname, "a+")
                    fout.write(r.text)
                    fout.close()
                else:
                    print("%s found !" % fname)
            else:
                print("%s not found ! (%i)" % (fname, r.status_code))
        except requests.ConnectionError:
            print("%s not available for %s" % (host, fname))

        fname = ffile.readline().strip()
