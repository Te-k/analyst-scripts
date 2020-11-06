import argparse
import requests


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Parse a list of websites and remove those not working')
    parser.add_argument('WEBSITEFILE', help='Text file with a list of websites')
    args = parser.parse_args()

    with open(args.WEBSITEFILE) as f:
        data = [a.strip() for a in f.read().split('\n')]

    for d in data:
        if d != '':
            try:
                if d.startswith('http'):
                    r = requests.get(d, timeout=5)
                else:
                    r = requests.get("http://{}/".format(d), timeout=5)
                if r.status_code == 200:
                    print(d)
            except requests.exceptions.ConnectionError:
                pass
            except requests.exceptions.ReadTimeout:
                pass
            except requests.exceptions.TooManyRedirects:
                pass
