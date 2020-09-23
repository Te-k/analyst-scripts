import json
import argparse

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Extract SHA1 kext and KnockKnock files')
    parser.add_argument('JSONFILE', help='JSON File saved by kext or knock knock')
    args = parser.parse_args()

    with open(args.JSONFILE) as f:
        data = json.loads(f.read())

    hashes = set()
    for k in data.keys():
        for l in data[k]:
            if "hashes" in l.keys():
                if 'sha1' in l['hashes']:
                    hashes.add(l['hashes']['sha1'])

    for l in hashes:
        print(l)
