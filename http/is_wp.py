#!/usr/bin/env python3
import requests
import argparse
import sys


def is_wp(domain):
    if not domain.startswith('http'):
        domain = 'http://' + domain + '/'

    try:
        r = requests.get(domain + '/wp-login.php')
        if r.status_code == 200:
            return True
        else:
            return False
    except requests.exceptions.ConnectionError:
        return False

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Check if a website is done with WordPress')
    subparsers = parser.add_subparsers(help='Subcommand')
    parser_a = subparsers.add_parser('domain', help='Information on a domain')
    parser_a.add_argument('DOMAIN', help='Domain')
    parser_a.set_defaults(subcommand='domain')
    parser_b = subparsers.add_parser('file', help='List of domains')
    parser_b.add_argument('FILE', help='File path')
    parser_b.set_defaults(subcommand='file')

    args = parser.parse_args()

    if 'subcommand' in args:
        if args.subcommand == 'domain':
            if is_wp(args.DOMAIN):
                print('Definively a Wordpress website')
            else:
                print('NOPE')
        elif args.subcommand == 'file':
            try:
                with open(args.FILE) as f:
                    data = f.read().split('\n')
            except FileNotFoundError:
                print('File does not exist')
                sys.exit(1)
            for d in data:
                if d.strip() == '':
                    continue
                if is_wp(d.strip()):
                    print('%s;Yes' % d.strip())
                else:
                    print('%s;No' % d.strip())
        else:
            parser.print_help()
    else:
        parser.print_help()
