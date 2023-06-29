import json

import requests
from IPy import IP

URL = "https://mullvad.net/en/servers/__data.json"


def is_ip(target):
    """
    Test if a string is an IP address
    """
    if isinstance(target, str):
        try:
            IP(target)
            return True
        except ValueError:
            return False
    else:
        return False


if __name__ == "__main__":
    r = requests.get(URL, stream=True)
    print("Hostname,ipv4,ipv6")
    for line in r.iter_lines():
        data = json.loads(line)

        for index in range(len(data.get("data", []))):
            if not isinstance(data["data"][index], str):
                continue
            if data["data"][index].endswith(".relays.mullvad.net"):
                try:
                    if is_ip(data["data"][index+1]):
                        ipv4 = data["data"][index+1]
                        ipv6 = data["data"][index+2]
                    elif is_ip(data["data"][index+4]):
                        ipv4 = data["data"][index+4]
                        ipv6 = data["data"][index+5]
                    elif is_ip(data["data"][index+2]):
                        ipv4 = data["data"][index+2]
                        ipv6 = data["data"][index+3]
                    else:
                        continue
                except IndexError:
                    continue
                print("{},{},{}".format(data["data"][index], ipv4, ipv6))
