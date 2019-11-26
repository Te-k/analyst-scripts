import argparse
import json
import requests

def get_virustotal_report(sha256):
    apikey = "233f22e200ca5822bd91103043ccac138b910db79f29af5616a9afe8b6f215ad"
    url = "https://www.virustotal.com/partners/sysinternals/file-reports?apikey={}".format(apikey)

    items = []
    items.append({
        "hash": sha256,
        "image_path": "unknown",
        "creation_datetime": "unknown",
    })
    headers = {"User-Agent": "VirusTotal", "Content-Type": "application/json"}
    res = requests.post(url, headers=headers, json=items)
    if res.status_code == 200:
        report = res.json()
        return report["data"][0]
    return None


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Process some integers.')
    parser.add_argument('JSONFILE', help='JSON File')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose mode')
    args = parser.parse_args()

    with open(args.JSONFILE) as f:
        data = json.loads(f.read())

    for package in data:
        if len(package['files']) > 0:
            for f in package['files']:
                res = get_virustotal_report(f['sha256'])
                if res:
                    if res['found']:
                        if res['positives'] > 0 or args.verbose:
                            print("{} - {} - Found {}".format(
                                package['name'],
                                f['sha256'],
                                res['detection_ratio']
                            ))
                    else:
                        print("{} - {} - Not on VT".format(package['name'], f['sha256']))
                else:
                    print("{} - {} - Problem querying VT".format(package['name'], f['sha256']))
        else:
            if args.verbose:
                print("{} - No File".format(package['name']))
