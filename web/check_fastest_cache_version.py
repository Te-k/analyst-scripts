import argparse
import requests


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Check if WP Fastest cache is installed and the version')
    parser.add_argument('DOMAIN', help="Domain")
    args = parser.parse_args()

    if args.DOMAIN.startswith("http"):
        domain = args.DOMAIN.rstrip("/") + "/"
    else:
        domain = "http://" + args.DOMAIN.rstrip("/") + "/"

    r = requests.get(domain + "wp-content/plugins/wp-fastest-cache/readme.txt")
    if r.status_code != 200:
        print("WP Fastest cache not found (HTTP {})".format(r.status_code))
    else:
        text = r.text
        version = text.split("\n")[6].split(" ")[2]
        if version != "1.2.2":
            print("/!\ Insecure Fastest Cache version: {}".format(version))
        else:
            print("Latest Fastest Cache version 1.2.2")
