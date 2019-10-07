#!/usr/bin/env python3
import requests
import argparse
import sys

TEST_PAGE = 'http://192.241.164.26/tools/open_proxy_check.txt'


def test_proxy(proxy, port):
    # Test HTTP first
    proxies = {'http': 'http://%s:%i' % (proxy, port)}
    try:
        r = requests.get(TEST_PAGE, proxies=proxies)
    except requests.exceptions.ProxyError:
        return False
    else:
        if r.status_code == 200:
            if 'If you are seeing this while running the open proxy text, your server is an open proxy.' in r.text:
                return True
        # This should not happen much
        return False


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Test an IP to check if it is an open proxy')
    subparsers = parser.add_subparsers(help='Subcommand')
    parser_a = subparsers.add_parser('ip', help='Check if an IP is an open proxy')
    parser_a.add_argument('IP', help='IP to be checked')
    parser_a.add_argument('--port', '-p', type=int, default=8080, help='Port')
    parser_a.set_defaults(subcommand='ip')
    parser_b = subparsers.add_parser('list', help='Check a list of IPs')
    parser_b.add_argument('FILE', help='File with a list of IP:port')
    parser_b.set_defaults(subcommand='list')
    parser_c = subparsers.add_parser('test', help='Test that the remote page is still up')
    parser_c.set_defaults(subcommand='test')

    args = parser.parse_args()

    if 'subcommand' in args:
        if args.subcommand == 'test':
            r = requests.get(TEST_PAGE)
            if r.status_code == 200:
                if 'If you are seeing this while running the open proxy text, your server is an open proxy.' in r.text:
                    print("It works!")
                else:
                    print("Bad bad bad: content has changed")
            else:
                print("Bad bad bad: not available")
        elif args.subcommand == 'list':
            try:
                with open(args.FILE) as f:
                    data = f.read().split('\n')
            except FileNotFoundError:
                print('This file does not exist')
                sys.exit(1)

            for proxy in data:
                if proxy.strip() == '':
                    continue
                try:
                    p = proxy.split(':')
                    port = int(p[1])
                except ValueError, IndexError:
                    print('%s - Invalid Value' % proxy)
                    continue
                if test_proxy(p[0].strip(), port):
                    print('%s - Yes' % proxy)
                else:
                    print('%s - No' % proxy)
        elif args.subcommand == 'ip':
            if test_proxy(args.IP, args.port):
                print('YES')
            else:
                print('NO')
        else:
            parser.print_help()
    else:
        parser.print_help()


