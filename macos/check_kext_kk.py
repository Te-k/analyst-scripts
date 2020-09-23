import json
import argparse

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Analyse kext and KnockKnock files')
    parser.add_argument('JSONFILE', help='JSON File saved by kext or knock knock')
    args = parser.parse_args()

    with open(args.JSONFILE) as f:
        data = json.loads(f.read())

    for k in data.keys():
        print("Checking {}".format(k))
        for l in data[k]:
            if "VT detection" in l:
                if not l["VT detection"].startswith("0/"):
                    print("Suspicious detection in VT:")
                    print(json.dumps(l, indent=4))
            else:
                print("Suspicious detection in VT:")
                print(json.dumps(l, indent=4))
