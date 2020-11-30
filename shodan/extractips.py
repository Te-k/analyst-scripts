import json
import argparse

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Extract IP addresses from Shodan results')
    parser.add_argument('JSONFILE', help='JSON File')
    args = parser.parse_args()

    line = "{}"
    with open(args.JSONFILE, 'r') as f:
        while line != "":
            data = json.loads(line)
            if "ip" in data:
                ip = data["ip"]
                print("{}.{}.{}.{}".format(
                    (ip >> 24) & 0xff,
                    (ip >> 16) & 0xff,
                    (ip >> 8) & 0xff,
                    ip & 0xff
                ))
            line = f.readline()
