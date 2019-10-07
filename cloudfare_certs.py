#!/usr/bin/env python3
from sslyze.server_connectivity_tester import ServerConnectivityError
from sslyze.server_connectivity_tester import ServerConnectivityTester
from sslyze.ssl_settings import TlsWrappedProtocolEnum
from sslyze.plugins.certificate_info_plugin import CertificateInfoScanCommand
from sslyze.synchronous_scanner import SynchronousScanner
from cryptography.x509 import DNSName, ExtensionOID
from dns import resolver, exception
import argparse
import sys


def get_cert_alt_names(host, port=443):
    try:
        server_tester = ServerConnectivityTester(hostname=host, port=port,
                            tls_wrapped_protocol=TlsWrappedProtocolEnum.HTTPS)
        server_info = server_tester.perform()
    except ServerConnectivityError:
        print("Impossible to connect")
        sys.exit(1)

    command = CertificateInfoScanCommand()
    synchronous_scanner = SynchronousScanner()
    scan_result = synchronous_scanner.run_scan_command(server_info, command)
    cert = scan_result.verified_certificate_chain[0]
    subj_alt_names = []
    san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    subj_alt_names = san_ext.value.get_values_for_type(DNSName)
    return subj_alt_names


def get_ns(domain):
    res = {}
    try:
        answers = resolver.query(domain, 'NS')
    except (resolver.NoAnswer, resolver.NXDOMAIN, resolver.NoNameservers):
        res['error'] = True
        res['msg'] = "No NS entry configured"
    except exception.Timeout:
        res['error'] = True
        res['msg'] = "Timeout"
    else:
        res['error'] = False
        res['ns'] = [str(b.target) for b in answers]
    return res


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Analyze cloudfare certs')
    parser.add_argument('HOST', help='host')
    args = parser.parse_args()

    res = get_ns(args.HOST)
    if res['error']:
        print(res['msg'])
        sys.exit(1)
    domain_ns = res['ns']
    print('NS: {}'.format(','.join(domain_ns)))

    alt_names = get_cert_alt_names(args.HOST)
    final_list = [b for b in alt_names if not b.startswith('*.') and 'cloudflaressl.com' not in b]
    for d in final_list:
        if d != args.HOST:
            res = get_ns(d)
            if res['error']:
                print('-{} - {}'.format(d, res['msg']))
            else:
                if res['ns'] == domain_ns:
                    print('-{} - SAME NS'.format(d))
                else:
                    print('-{} - different NS'.format(d))
