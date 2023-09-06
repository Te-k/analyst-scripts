import argparse
import requests
import json

# Inspired by https://github.com/Malfrats/xeuledoc/tree/master


def get_info(_id: str):
    """
    Get information about an URL and returns info about it
    """
    headers = {
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36",
        "X-Origin": "https://drive.google.com"
    }
    r = requests.get(
        "https://clients6.google.com/drive/v2beta/files/{}?fields=alternateLink%2CcopyRequiresWriterPermission%2CcreatedDate%2Cdescription%2CdriveId%2CfileSize%2CiconLink%2Cid%2Clabels(starred%2C%20trashed)%2ClastViewedByMeDate%2CmodifiedDate%2Cshared%2CteamDriveId%2CuserPermission(id%2Cname%2CemailAddress%2Cdomain%2Crole%2CadditionalRoles%2CphotoLink%2Ctype%2CwithLink)%2Cpermissions(id%2Cname%2CemailAddress%2Cdomain%2Crole%2CadditionalRoles%2CphotoLink%2Ctype%2CwithLink)%2Cparents(id)%2Ccapabilities(canMoveItemWithinDrive%2CcanMoveItemOutOfDrive%2CcanMoveItemOutOfTeamDrive%2CcanAddChildren%2CcanEdit%2CcanDownload%2CcanComment%2CcanMoveChildrenWithinDrive%2CcanRename%2CcanRemoveChildren%2CcanMoveItemIntoTeamDrive)%2Ckind&supportsTeamDrives=true&enforceSingleParent=true&key=AIzaSyC1eQ1xj69IdTMeii5r7brs3R90eck-m7k".format(_id),
        headers=headers
    )
    if r.status_code != 200:
        print("Invalid answer: {}".format(r.status_code))
        print(r.text)
        return {}
    return r.json()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Get information about a shared document')
    parser.add_argument("DOCID", help="ID of the doc")
    args = parser.parse_args()

    print(json.dumps(get_info(args.DOCID), indent=4))
