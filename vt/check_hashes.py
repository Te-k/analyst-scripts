import os
import argparse
import requests



def get_virustotal_report(hashes):
    apikey = "233f22e200ca5822bd91103043ccac138b910db79f29af5616a9afe8b6f215ad"
    url = "https://www.virustotal.com/partners/sysinternals/file-reports?apikey={}".format(apikey)

    items = []
    for sha256 in hashes:
        items.append({
            "hash": sha256,
            "image_path": "unknown",
            "creation_datetime": "unknown",
        })
    headers = {"User-Agent": "VirusTotal", "Content-Type": "application/json"}
    res = requests.post(url, headers=headers, json=items)

    if res.status_code == 200:
        report = res.json()
        return report["data"]

    return None

def chunks(lst, n):
    """Yield successive n-sized chunks from lst."""
    for i in range(0, len(lst), n):
        yield lst[i:i + n]


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Process some hashes')
    parser.add_argument('FILE', help='File')
    args = parser.parse_args()

    with open(args.FILE, 'r') as infile:
        data = infile.read().split()
    hash_list = list(set([a.strip() for a in data]))

    print("Hash,Found,Detection,Total AV,Link")
    for l in chunks(hash_list, 25):
        res = get_virustotal_report(l)
        if res:
            for r in res:
                if r["found"]:
                    print("%s,Found,%i,%i,%s" % (
                        r['hash'],
                        r['positives'],
                        r['total'],
                        r['permalink']
                    ))
                else:
                    print("%s,Not found,,," % r['hash'])
        else:
            print("Query failed somehow!")
