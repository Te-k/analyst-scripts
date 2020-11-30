import os
import requests
import sys
import argparse
import xml.etree.ElementTree as ET
import tempfile
import zipfile
from datetime import datetime
from io import BytesIO


def get_list():
    """
    Download list of available data from
    https://archive.org/services/search/v1/scrape?debug=false&xvar=production&total_only=false&count=10000&fields=identifier%2Citem_size&q=Urlteam%20Release
    """
    r = requests.get("https://archive.org/services/search/v1/scrape?debug=false&xvar=production&total_only=false&count=10000&fields=identifier%2Citem_size&q=Urlteam%20Release")
    return r.json()


def download_daydata(identifier, outpath, verbose):
    """
    get the list of zip files from the xml
    then download data
    """
    r = requests.get('https://archive.org/download/{}/{}_files.xml'.format(identifier, identifier))
    root = ET.fromstring(r.text)
    for fname in [f.get('name') for f in root.findall('file')]:
        if fname.endswith('.zip'):
            # Download
            if verbose:
                print("Downloading {}".format(fname))
            r = requests.get("https://archive.org/download/{}/{}".format(identifier, fname))
            if r.status_code == 200:
                data = BytesIO(r.content)
                input_zip = zipfile.ZipFile(data)
                txts = [f for f in input_zip.namelist() if "_.txt.xz" in f]
                i = 0
                for txt in txts:
                    op = os.path.join(outpath, os.path.splitext(fname)[0] + "_" + str(i) + ".xz")
                    if not os.path.isfile(op):
                        with open(op, "wb+") as f:
                            f.write(input_zip.read(txt))
                        if verbose:
                            print("Archive extracted in {}".format(op))
                    else:
                        print("{} already exists".format(op))
                    i += 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Download data from urlteam')
    parser.add_argument('--since', '-s', help='Date from where to download files (format YYYYMMDD)')
    parser.add_argument('--until', '-u', help="Download data until (default is now)")
    parser.add_argument('--output', '-o', help="Output folder (default is .)", default=".")
    #parser.add_argument('--no-cleaning', '-n', help="Do not extract xz archive from zip", action="store_true")
    parser.add_argument('--verbose', '-v', help="Verbose mode", action="store_true")
    parser.add_argument('--all', '-a', help="Download everything", action="store_true")
    args = parser.parse_args()

    if not args.all:
        try:
            since = datetime(int(args.since[:4]), int(args.since[4:6]), int(args.since[6:8]))
        except (TypeError, ValueError):
            print("Bad since input value")
            sys.exit(1)

        if args.until:
            try:
                until = datetime(int(args.until[:4]), int(args.until[4:6]), int(args.until[6:8]))
            except (TypeError, ValueError):
                print("Bad until input value")
                sys.exit(1)
        else:
            until = datetime.now()

    if not os.path.isdir(args.output):
        print("Invalid output folder")
        sys.exit(1)

    for day in get_list()['items']:
        if args.all:
            if args.verbose:
                print("Starting to download identifier {}".format(day['identifier']))
            download_daydata(day['identifier'], args.output, args.verbose)
        else:
            if day['identifier'].startswith('urlteam_'):
                print(day)
                d = datetime(*map(int, day['identifier'][8:].split('-')))
                if d > since and d < until:
                    if args.verbose:
                        print("Starting to download identifier {}".format(day['identifier']))
                    download_daydata(day['identifier'], args.output, args.verbose)
