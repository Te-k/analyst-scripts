#! /usr/bin/env python2

import argparse
from urlparse import urlparse
import requests
from datetime import datetime
import time


def get_response_time(host):
    now = datetime.now()
    try:
        response = requests.get(host.geturl())
        if response.status_code == 200:
            print "%s - %s : Time Response: %f" % (str(now.time()),host.netloc, response.elapsed.total_seconds())
            return (True, response.elapsed)
        else:
            print "%s - %s : Error server not available" % (str(now.time()), host.netloc)
            return (False, 0.0)
    except requests.exceptions.ConnectionError:
        print "%s - %s : Fail to reach the server!" % (str(now.time()), host.netloc)
        return (False, 0.0)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Watch web server response time')
    parser.add_argument('-l', '--log', help='Log response times over time', action='store_true')
    parser.add_argument('-o', '--once', help='Do not watch, just print response time and quit', action="store_true")
    parser.add_argument('-d', '--delay', help='Delay between request in seconds(default is 60)', type=int, default=60)
    parser.add_argument('-a', '--alerts', help='Display alerts when response time goes over 4s', action="store_true")
    parser.add_argument('host', metavar='HOST',  help='Host targeted')
    args = parser.parse_args()

    # valid the host
    if args.host.startswith("http"):
        host = urlparse(args.host)
    else:
        host = urlparse("http://" + args.host)

    if args.log:
        flog = open(host.netloc + ".log", "a")


    #print args
    if args.alerts:
        import pynotify
        pynotify.init("icon-summary-body")

    if args.once:
        get_response_time(host)
    else:
        while True:
            (res, t) = get_response_time(host)
            if args.alerts and res and (t.total_seconds() > 4):
                notification = pynotify.Notification(
                    host.netloc,
                    "Response time : %f !!!!!!!!!!!!!!!" % t.total_seconds(),
                    "notification-message-im")
                notification.show()
                del notification
            if args.log:
                # fail handle appends
                now = datetime.now()
                if res:
                    flog.write(now.strftime("%Y-%m-%d %H:%M:%S\t->\t") + str(t.total_seconds())+ "\n")
                else:
                    flog.write(now.strftime("%Y-%m-%d %H:%M:%S\t->\t") + "0.0\n")
                flog.flush()
            time.sleep(args.delay)
