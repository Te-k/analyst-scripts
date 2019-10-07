#! /usr/bin/python3
import os
import sys
import argparse
import hashlib
from androguard.core.bytecodes.apk import APK
from androguard.core import androconf


def get_package_name(apk_path):
    """
    Extract the package name of an APK
    """
    a = APK(apk_path)
    return a.get_package(), a.get_androidversion_code()


def get_sha256(path):
    """
    Get SHA256 hash of the given file
    """
    m = hashlib.sha256()
    with open(path, 'rb') as fin:
        m.update(fin.read())
    return m.hexdigest()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("PATH", help="Path to a file or folder")
    args = parser.parse_args()

    if os.path.isdir(args.PATH):
        for f in os.listdir(args.PATH):
            if os.path.isfile(f):
                if androconf.is_android(os.path.join(args.PATH, f)) == 'APK':
                    pkg_name, pkg_version = get_package_name(os.path.join(args.PATH, f))
                    print('{:45} - {:20} - {}'.format(
                            f,
                            pkg_name,
                            pkg_version
                        )
                    )

        pass
    elif os.path.isfile(args.PATH):
        print("File:\t {}".format(os.path.basename(args.PATH)))
        print("SHA256:\t {}".format(get_sha256(args.PATH)))
        pkg_name, pkg_version = get_package_name(args.PATH)
        print("Package: {}".format(pkg_name))
        print("Version: {}".format(pkg_version))
    else:
        print("Invalid path")
        sys.exit(-1)
