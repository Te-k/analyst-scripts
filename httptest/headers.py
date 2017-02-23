#! /usr/bin/env python2
import argparse
import os
import socket
from urlparse import urlparse


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Get HTTP headers')
    parser.add_argument('host', metavar='HOST',  help='Host targeted')
    args = parser.parse_args()

    # valid the host
    hosturl = urlparse(args.host)
    if hosturl.netloc == '':
        # XXX: remove path after hostname
        host = hosturl.path
    else:
        host = hosturl.netloc


    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # FIXME : does not support HTTPs
    s.connect((host, 80))
    s.sendall("GET / HTTP/1.1\r\nHost: %s\r\n\r\n" % host)
    data = s.recv(100000)
    s.close()

    sep = data.find("\r\n\r\n")
    headers = data[:sep]
    content = data[sep+4:]

    print(headers)
