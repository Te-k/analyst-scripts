#! /usr/bin/python3
import sys
import argparse
from androguard.core.bytecodes import apk
from androguard.core import androconf
from androguard.core.bytecodes.axml import ARSCParser
from lxml import etree


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("PATH", help="Path of the resource file")
    args = parser.parse_args()

    ret_type = androconf.is_android(args.PATH)
    if ret_type == "APK":
        a = apk.APK(args.PATH)
        arscobj = a.get_android_resources()
        if not arscobj:
            print("The APK does not contain a resources file!", file=sys.stderr)
            sys.exit(0)
    elif ret_type == "ARSC":
        with open(args.PATH, 'rb') as fp:
            arscobj = ARSCParser(fp.read())
            if not arscobj:
                print("The resources file seems to be invalid!", file=sys.stderr)
                sys.exit(1)
    else:
        print("Unknown file type!", file=sys.stderr)
        sys.exit(1)

    xmltree = arscobj.get_public_resources(arscobj.get_packages_names()[0])
    x = etree.fromstring(xmltree)
    for elt in x:
        if elt.get('type') == 'string':
            val = arscobj.get_resolved_res_configs(int(elt.get('id')[2:], 16))[0][1]
            print('{}\t{}\t{}'.format(
                elt.get('id'),
                elt.get('name'),
                val
            ))
