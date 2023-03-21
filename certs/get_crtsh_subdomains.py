#!/usr/bin/env python3
import argparse
import psycopg2

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Get subdomains of a domain from crt.sh certificates')
    parser.add_argument('DOMAIN', help='Domain')
    args = parser.parse_args()

    subdomains = []
    conn = psycopg2.connect("dbname=certwatch user=guest host=crt.sh")
    conn.set_session(autocommit=True)
    cur = conn.cursor()
    # Tips from Randorisec https://www.randori.com/blog/enumerating-subdomains-with-crt-sh/
    cur.execute("""
        select distinct(lower(name_value))
        FROM certificate_and_identities cai
        WHERE plainto_tsquery('{}') @@ identities(cai.CERTIFICATE) AND
            lower(cai.NAME_VALUE) LIKE ('%.{}')
    """.format(args.DOMAIN, args.DOMAIN))
    for entry in cur.fetchall():
        if entry[0].startswith("*.") and not keep_wildcard:
            continue
        subdomains.append(entry[0])

    for p in subdomains:
        print(p)
