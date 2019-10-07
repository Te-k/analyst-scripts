#!/usr/bin/env python3
import argparse
import requests
import json

def get_info(phone):
    r = requests.get(
        "https://search5.truecaller.com/v2/search",
        params = {
            "q":phone,
            "countryCode": "",
            "type": 4,
            "locAddr": "",
            "placement": "SEARCHRESULTS,HISTORY,DETAILS",
            "adId": "",
            "clientId": 1,
            "myNumber": "lS59d72f4d1aefae62ba0c1979l_Dl7_DEj9CPstICL1dRnD",
            "registerId": "645710775"
        }
    )
    return r.json()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("PHONE")
    args = parser.parse_args()

    print(json.dumps(get_info(args.PHONE), indent=4, sort_keys=True))
