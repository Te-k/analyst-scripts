import os
import sys
import argparse
from androguard.core import androconf
from androguard.misc import AnalyzeAPK


# Ref : https://stackoverflow.com/questions/48090841/security-metadata-in-android-apk/51857027#51857027
BLOCK_TYPES = {
    0x7109871a: 'SIGNv2',
    0xf05368c0: 'SIGNv3',
    0x2146444e: 'Google Metadata',
    0x42726577: 'Padding'
}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Process some apks')
    parser.add_argument('APK', help='APK')
    args = parser.parse_args()


    if os.path.isdir(args.APK):
        for f in os.listdir(args.APK):
            apk_path = os.path.join(args.APK, f)
            if os.path.isfile(apk_path):
                if androconf.is_android(apk_path) == 'APK':
                    a, d, dx = AnalyzeAPK(apk_path)
                    a.is_signed_v2()
                    if 0x2146444e in a._v2_blocks:
                        print("{} : FROSTING".format(f))
                    else:
                        print("{} : NOPE".format(f))
                else:
                    print("{} not an APK".format(f))
    else:
        if androconf.is_android(args.APK) == 'APK':
            a, d, dx = AnalyzeAPK(args.APK)
            if a.is_signed_v1():
                print("V1 Signature")
            if a.is_signed_v2():
                print("V2 Signature")
            if a.is_signed_v3():
                print("V3 Signature")
            print("")
            print("Signing Blocks:")
            for b in a._v2_blocks:
                if b in BLOCK_TYPES.keys():
                    print("\t{}".format(BLOCK_TYPES[b]))
                else:
                    print("\tUnknown block {}".format(hex(b)))
        else:
            print("Not an APK file")
