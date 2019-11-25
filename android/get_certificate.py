#! /usr/bin/python3
import os
import sys
import argparse
from androguard.core.bytecodes.apk import APK
from androguard.core import androconf


def convert_x509_name(name):
    """
    Convert x509 name to a string
    """
    types = {
        'country_name': 'C',
        'state_or_province_name': 'ST',
        'locality_name': 'L',
        'organization_name': 'O',
        'organizational_unit_name': 'OU',
        'common_name': 'CN',
        'email_address': 'emailAddress'
    }

    return '/'.join(['{}={}'.format(types[attr], name.native[attr]) for attr in name.native])


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("APK", help="Path to an APK file")
    args = parser.parse_args()

    if not os.path.isfile(args.APK):
        print("Invalid file path")
        sys.exit(-1)

    apk = APK(args.APK)

    if len(apk.get_certificates()) > 0:
        cert = apk.get_certificates()[0]
        print("SHA1: {}".format(cert.sha1_fingerprint.replace(' ', '')))
        print('Serial: {:X}'.format(cert.serial_number))
        print("Issuer: {}".format(convert_x509_name(cert.issuer)))
        print("Subject: {}".format(convert_x509_name(cert.subject)))
        print("Not Before: {}".format(cert['tbs_certificate']['validity']['not_before'].native.strftime('%b %-d %X %Y %Z')))
        print("Not After: {}".format(cert['tbs_certificate']['validity']['not_after'].native.strftime('%b %-d %X %Y %Z')))
    else:
        print("No certificate here, weird")
