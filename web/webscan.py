import argparse
import requests
import yara
from io import StringIO
from urllib.parse import urljoin, urlparse
from lxml import etree


def extract_suburls(webpage, url):
    """
    Extract javascript links from every page
    """
    if webpage.strip() == "":
        return set()
    urlp = urlparse(url)
    parser = etree.HTMLParser()
    tree   = etree.parse(StringIO(webpage), parser)
    res = set()
    for s in tree.xpath('//script[@src]/@src'):
        if s.startswith('http'):
            parsed = urlparse(s)
            if parsed.netloc == urlp.netloc:
                res.add(s)
        else:
            res.add(urljoin(url, s))
    return res


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Scan a website for a specific yara rule')
    parser.add_argument('URL', help='URL of the website to scan')
    parser.add_argument('YARARULE', help='Yara rule')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose mode')
    args = parser.parse_args()

    # TODO : split the url likely

    todo = set([args.URL])
    done = set()

    rules = yara.compile(filepath=args.YARARULE)
    found = []

    while len(todo) > 0:
        url = todo.pop()
        if args.verbose:
            print("Scanning {}".format(url))
        r = requests.get(url)
        if r.status_code != 200:
            if args.verbose:
                print("{} : HTTP code {}".format(url, r.status_code))
            continue
        webpage = r.text
        done.add(url)
        sublinks = extract_suburls(webpage, args.URL)
        for s in sublinks:
            if s not in done:
                todo.add(s)

        # Yara scan
        res = rules.match(data=webpage)
        if len(res) > 0:
            print("{} matches {}".format(url, ", ".join([r.rule for r in res])))
            found.append([url, ", ".join([r.rule for r in res])])

    if args.verbose:
        print("\n")
    if len(found) > 0:
        print("FOUND !")
        for f in found:
            print("{} - {}".format(f[0], f[1]))
    else:
        print("Nothing found")
    print("")
