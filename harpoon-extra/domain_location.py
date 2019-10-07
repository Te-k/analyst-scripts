#!/usr/bin/env python3
import argparse
import sys
import os
from dns import resolver, reversename
from harpoon.commands.ip import CommandIp


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Give information on domain location')
    parser.add_argument('FILE', help='File containing domain list')
    args = parser.parse_args()

    if not os.path.isfile(args.FILE):
        print('File does not exist')
        sys.exit(1)

    with open(args.FILE, 'r') as f:
        data = f.read().split('\n')

    cip = CommandIp()

    print('Domain;IP;ASN;AS Name;Country;City')
    for domain in data:
        try:
            answers = resolver.query(domain, 'A')
        except (resolver.NoAnswer, resolver.NXDOMAIN):
            print("%s;;;;;" % domain)
        except resolver.NoNameservers:
            print("%s;;;;;" % domain)
        else:
            for rdata in answers:
                info = cip.ipinfo(rdata.address)
                print("%s;%s;%i;%s;%s;%s" % (
                        domain,
                        rdata.address,
                        info['asn'],
                        info['asn_name'],
                        info['country'],
                        info['city']
                    )
                )
