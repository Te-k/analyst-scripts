import sys
import argparse
from datetime import datetime
from censys.search import CensysHosts


INTERESTING_ATTRIBUTES = [
    "services.banner",
    "services.software.product",
    "services.software.other.comment",
    "services.software.vendor",
    "services.ssh.endpoint_id.raw",
    "services.ssh.endpoint_id.software_version",
    "services.ssh.endpoint_id.comment",
    "services.ssh.server_host_key.fingerprint_sha256",
    "services.http.response.status_code",
    "services.http.response.headers.Content_Length",
    "services.http.response.headers.Server",
    "services.http.response.body_hashes",
    "services.http.response.body_hash",
    "services.http.response.html_title",
    "services.jarm.fingerprint",
    "services.jarm.cipher_and_version_fingerprint",
    "services.jarm.tls_extensions_sha256",
    "services.tls.certificates.leaf_data.names",
    "services.tls.certificates.leaf_data.names",
    "services.tls.certificates.leaf_data.subject_dn",
    "services.tls.certificates.leaf_data.issuer_dn",
    "services.tls.certificates.leaf_data.tbs_fingerprint",
    "services.tls.certificates.leaf_data.issuer.organization",
    "services.tls.certificates.chain.fingerprint",
    "services.tls.ja3s"
]


def convert_data(data, key):
    res = []
    if isinstance(data, list):
        for entry in data:
            res += convert_data(entry, key)
        return res
    if isinstance(data, dict):
        for k in data:
            if key == "":
                res += convert_data(data[k], k)
            else:
                res += convert_data(data[k], key + "." + k)
        return res
    return [(key, data)]


def convert_host_data(host, f=False):
    """
    Convert data from a service into a list of fields
    So far only implements ssh and http
    """
    all_data = []
    for service in host["services"]:
        for (k, v) in convert_data(service, "services"):
            if f:
                if k in INTERESTING_ATTRIBUTES:
                    all_data.append((service["port"], k, v))
            else:
                all_data.append((service["port"], k, v))

    return all_data


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Compare Censys hosts')
    parser.add_argument('HOST', nargs='+', help='IP addresses')
    parser.add_argument(
        '--all', '-a', action="store_false",
        help="Check all fields available")
    parser.add_argument('--verbose', '-v', action="store_true", help="verbose mode")
    parser.add_argument('--date', '-d', help="date of the check in RFC3339 timestamp (2021-03-01T17:49:05Z)")
    args = parser.parse_args()

    h = CensysHosts()
    if len(args.HOST) < 2:
        print("Need more HOSTS")
        sys.exit(-1)

    if args.date:
        try:
            datetime.strptime(args.date, "%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            print("Invalid date format, it should be in RFC3339 timestamp format : 2021-03-01T17:49:05Z")
            sys.exit(1)

    first_ip = args.HOST.pop()
    if args.date:
        first = h.view(first_ip, at_time=args.date)
    else:
        first = h.view(first_ip)
    intersect = convert_host_data(first, f=args.all)
    print("Host {} : {} entries".format(first_ip, len(intersect)))
    for host in args.HOST:
        if args.date:
            hdata = h.view(host, at_time=args.date)
        else:
            hdata = h.view(host)
        hdatad = convert_host_data(hdata, f=args.all)
        print("Host {} : {} entries".format(host, len(hdatad)))
        intersect = set(intersect).intersection(hdatad)

    print("Intersect data: {}".format(len(intersect)))

    for port in sorted(set([a[0] for a in intersect])):
        print("------------------ {}".format(port))
        for dd in sorted(intersect, key=lambda x: x[1]):
            if dd[0] == port:
                if isinstance(dd[2], str):
                    if ("\n" in dd[2]) or ("\r" in dd[2]):
                        print("{}=\"{}\"".format(dd[1], repr(dd[2])))
                    else:
                        print("{}=\"{}\"".format(dd[1], dd[2]))
                else:
                    print("{}={}".format(dd[1], dd[2]))
        print("")
