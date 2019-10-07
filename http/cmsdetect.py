#!/usr/bin/env python3
import argparse
import random
import string
import requests
from urllib.parse import urljoin

SIGNATURES = {
    'wordpress': ['wp-admin', 'wp-login.php'],
    'drupal': ['CHANGELOG.txt', '/user/login', '/user/register', '/node/'],
    # 'opencart': ['index.php?route']
    # 'Joomla': ['option=com_']
}

USERAGENT = 'CMS-Detect/v0.1'
headers = {'User-Agent': USERAGENT}


def detect(domain, page):
    r = requests.get(urljoin(domain, page), headers=headers)
    return r.status_code


def check_random_page(domain):
    random_string = ''.join(
            random.choice(string.ascii_lowercase + string.digits)
            for _ in range(15)
            )
    r = requests.get(urljoin(domain, random_string), headers=headers)
    return r.status_code


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Detect a CMS')
    parser.add_argument('DOMAIN', help='domain')
    parser.add_argument(
        '--test', '-t', choices=['drupal', 'wordpress', 'all'],
        default='all', help='List of CMS to be tested'
    )
    args = parser.parse_args()

    if not args.DOMAIN.startswith('http'):
        target = 'http://' + args.DOMAIN
    else:
        target = args.DOMAIN

    s = check_random_page(target)
    if s == 200:
        print("Returns 200 for non-existing pages, this script is useless")

    if args.test == 'all':
        for cms in SIGNATURES:
            print(cms.capitalize())
            for i in SIGNATURES[cms]:
                print("\t%s - %i" % (urljoin(target, i), detect(target, i)))
    else:
        for i in SIGNATURES[args.test]:
            print("%s - %i" % (urljoin(target, i), detect(target, i)))
