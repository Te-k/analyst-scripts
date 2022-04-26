import argparse
import requests
import os

def get_key():
    path = os.path.expanduser("~/.pithus")
    if os.path.isfile(path):
        with open(path) as f:
            return f.read().strip()
    return None


class Pithus(object):
    def __init__(self, api_key):
        self.api_key = api_key
        self.base_url = "https://beta.pithus.org/api/"

    def send(self, data):
        files = {"file": data}
        headers = {"Authorization": "Token " + self.api_key}
        r = requests.post(self.base_url + "upload", files=files, headers=headers)
        if r.status_code != 200:
            raise Exception("Booo, that didn't work, HTTP code {}".format(r.status_code))
        return r.json()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Upload an APK to Pithus")
    parser.add_argument("FILEPATH", help="File path")
    args = parser.parse_args()

    pithus = Pithus(get_key())
    with open(args.FILEPATH, "rb") as f:
        data = f.read()

    try:
        r = pithus.send(data)
    except Exception as r:
        print("Upload failed")
        print(e)
    else:
        print("Upload success")
        print("https://beta.pithus.org/report/" + r["file_sha256"])
