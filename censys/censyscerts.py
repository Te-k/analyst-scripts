import censys.certificates
import argparse
import os
import json
from censyslib import *

def print_certificate(cert, verbose=False):
    if verbose:
        print json.dumps(cert, sort_keys=True, indent=4, separators=(',', ': '))
    else:
        try:
            print('----------  %s-------------' % cert["parsed"]["subject_dn"])
            print("Subject CN: %s" % cert["parsed"]["subject_dn"])
            print("Issuer: %s (%s)" % (
                    ",".join(cert["parsed"]["issuer"]["common_name"]),
                    ",".join(cert["parsed"]["issuer"]["organization"])
                )
            )
            print("Starts: %s" % cert["parsed"]["validity"]["start"])
            print("End: %s" % cert["parsed"]["validity"]["end"])
            if "subject_alt_name" in cert["parsed"]["extensions"]:
                print("Alt names: %s" % ",".join(cert["parsed"]["extensions"]["subject_alt_name"]["dns_names"]))
            print("Valid certificate: %s" % cert["valid_nss"])
            print("")
            print('Parent certificate: %s' % ",".join(cert["parents"]))
            print('SHA256: %s' % cert['parsed']['fingerprint_sha256'])
            if cert["parsed"]["extensions"]["basic_constraints"]["is_ca"]:
                print("Basic Constraints: Yes, CA")
        except:
            print("Bug, displaying everything")
            print json.dumps(cert, sort_keys=True, indent=4, separators=(',', ': '))

def search(term, max=25):
    res = cc.search('"%s"' % term)
    lst = []
    try:
        for i in range(max):
            lst.append(res.next())
    except StopIteration:
        pass

    return lst

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Request censys certificates')
    parser.add_argument('--search', '-s', help='Search term in Censys database')
    parser.add_argument('--id', '-i', help='Check for certificate id')
    parser.add_argument('--file', '-f', help='Search for certs based on a domain list in a file')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose mode')
    args = parser.parse_args()

    key = get_apikey()


    cc = censys.certificates.CensysCertificates(api_id=key[0], api_secret=key[1])
    if args.search is not None:
        lst = search(args.search)

        if len(lst) == 1:
            cert = cc.view(lst[0]["parsed.fingerprint_sha256"][0])
            print_certificate(cert, args.verbose)
        else:
            if len(lst) == 25:
                print("Results: > 25 results\n")
            else:
                print("Results: %i results\n" % len(lst))

            for cert in lst:
                print(cert["parsed.fingerprint_sha256"][0])
                print("\t SubjectDN: %s" % ",".join(cert["parsed.subject_dn"]))
                print("\t IssuerDN: %s\n" % ",".join(cert["parsed.issuer_dn"]))
    elif args.id is not None:
        cert = cc.view(args.id)
        print_certificate(cert, args.verbose)
    elif args.file is not None:
        domains = open(args.file, "r").read().split('\n')
        domains = filter(lambda x: x!= '', map(lambda x:x.strip(), domains))
        for domain in domains:
            lst = search(domain)
            if len(lst) == 0:
                print("%s: cert not found" % domain)
            elif len(lst) == 1:
                print("%s: cert found %s" % (domain, lst[0]["parsed.fingerprint_sha256"][0]))
            else:
                print("%s: %i certificates found" % (domain, len(lst)))

    else:
        parser.print_help()
