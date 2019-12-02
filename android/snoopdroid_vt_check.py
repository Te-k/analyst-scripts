import argparse
import json
import requests
import shutil
import os


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
    parser.add_argument('--sort', '-s', action='store_true', help='Sort suspicious files in a different folders')
    parser.add_argument('--input', '-i', help='Input folder to sort files', default='apks')
    args = parser.parse_args()

    with open(args.JSONFILE) as f:
        data = json.loads(f.read())

    if args.sort:
        if not os.path.isdir('results'):
            os.mkdir('results')
        os.mkdir('results/clean')
        os.mkdir('results/unknown')
        os.mkdir('results/suspicious')

    for package in data:
        if len(package['files']) > 0:
            for f in package['files']:
                res = get_virustotal_report(f['sha256'])
                in_path = os.path.join(args.input, os.path.basename(f['stored_path']))
                if res:
                    if res['found']:
                        if res['positives'] > 0 or args.verbose:
                            print("{} - {} - Found {}".format(
                                package['name'],
                                f['sha256'],
                                res['detection_ratio']
                            ))
                        if args.sort:
                            if os.path.isfile(in_path):
                                if res['positives'] > 0:
                                    shutil.move(in_path, os.path.join('results', 'suspicious', os.path.basename(f['stored_path'])))
                                else:
                                    shutil.move(in_path, os.path.join('results', 'clean', os.path.basename(f['stored_path'])))
                            else:
                                print("Weird, {} does not exist".format(in_path))

                    else:
                        print("{} - {} - Not on VT".format(package['name'], f['sha256']))
                        if args.sort:
                            if os.path.isfile(in_path):
                                shutil.move(in_path, os.path.join('results', 'unknown', os.path.basename(f['stored_path'])))
                            else:
                                print("Weird, {} does not exist".format(in_path))

                else:
                    print("{} - {} - Problem querying VT".format(package['name'], f['sha256']))
        else:
            if args.verbose:
                print("{} - No File".format(package['name']))
