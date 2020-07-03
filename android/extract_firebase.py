#! /usr/bin/python3
import os
import sys
import argparse
from androguard.core.bytecodes import apk
from androguard.core import androconf
from androguard.core.bytecodes.axml import ARSCParser
from lxml import etree


def get_firebase(fpath):
    a = apk.APK(fpath)
    arscobj = a.get_android_resources()
    if not arscobj:
        return None
    xmltree = arscobj.get_public_resources(arscobj.get_packages_names()[0])
    x = etree.fromstring(xmltree)
    for elt in x:
        if elt.get('type') == 'string':
            val = arscobj.get_resolved_res_configs(int(elt.get('id')[2:], 16))[0][1]
            if val.endswith('firebaseio.com'):
                return val
    return None


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("PATH", help="Path of a folder")
    args = parser.parse_args()


    if os.path.isdir(args.PATH):
        for f in os.listdir(args.PATH):
            fpath = os.path.join(args.PATH, f)
            if os.path.isfile(fpath):
                if androconf.is_android(fpath) == 'APK':
                    r = get_firebase(fpath)
                    if r:
                        print("{} : {}".format(fpath, r))
    elif os.path.isfile(args.PATH):
        if androconf.is_android(args.PATH) == 'APK':
            r = get_firebase(args.PATH)
            if r:
                print(r)
    else:
        print("Please give an APK file or a folder")
