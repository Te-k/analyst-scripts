import requests
import argparse
from datetime import datetime


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
            description='Check PGP key of a protonmail account')
    parser.add_argument('EMAIL', help="Protonmail email")
    args = parser.parse_args()

    r = requests.get(
            'https://api.protonmail.ch/pks/lookup?op=index&search={}'.format(
                args.EMAIL))
    res = r.text
    if res.startswith("info:1:0"):
        print("This email address doesn't exist")
    else:
        print(res)
        creation = res.split("\r\n")[1].split(":")[4]
        d = datetime.fromtimestamp(int(creation))
        print("Creation date: {}".format(d))
