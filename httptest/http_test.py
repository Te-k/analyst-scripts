#! /usr/bin/env python2
import argparse
import os
import socket
from urlparse import urlparse

def get_request(num, host):
    if num == 0:
        # Default request
        return "GET / HTTP/1.1\r\nHost: %s\r\n\r\n" % host
    elif num == 1:
        # HTTP 1.0 without HOST HEADER
        return "GET / HTTP/1.0\r\n\r\n"
    elif num == 2:
        return "GET / HTTP/1.0\r\nHost: %s\r\n\r\n" % host
    elif num == 3:
        return "OPTIONS / HTTP/1.1\r\nHost: %s\r\n\r\n" % host
    elif num == 4:
        return "TRACE / HTTP/1.1\r\nHost: %s\r\n\r\n" % host
    elif num == 5:
        return "FOOBAR / HTTP/1.1\r\nHost: %s\r\n\r\n" % host
    else:
        return ""

def send_request(num, host, args):
    req = get_request(num, host)
    if req == "":
        print "Bad number"
        exit(1)
    else:
        print "========================================"
        print "Request #%i to %s\n" % (num, host)
        print req

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, 80))
    s.sendall(req)
    #FIXME : does not get all
    data = s.recv(100000)
    s.close()

    sep = data.find("\r\n\r\n")
    headers = data[:sep]
    content = data[sep+4:]

    if args.content:
        print data
    else:
        if len(content) < 700:
            print data
        else:
            print headers
            print "\nContent avoided (length %i)" % len(content)
    print ""


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Make some weird raw HTTP requests and print outputs')
    parser.add_argument('-a', '--all', help='Send all requests', action='store_true')
    parser.add_argument('-n', '--num', help='Select only one request to send [1-2]', type=int)
    parser.add_argument('-c', '--content', help='Always show the content', action="store_true")
    parser.add_argument('host', metavar='HOST',  help='Host targeted')
    args = parser.parse_args()

    # valid the host
    hosturl = urlparse(args.host)
    if hosturl.netloc == '':
        # XXX: remove path after hostname
        host = hosturl.path
    else:
        host = hosturl.netloc

    DEFAULT = [0, 1]
    ALL = [0, 1, 2]

    if args.num != None:
        # Only one request
        send_request(args.num, host, args)
    else:
        if args.all:
            requests = ALL
        else:
            requests = DEFAULT

        for i in requests:
            send_request(i, host, args)
