#! /usr/bin/python2
import argparse
import lief
import os
import datetime
import magic
import pefile
import hashlib


def extract_datetime(pe):
    """
    Extract PE timestamp using lief
    """
    if pe.header.time_date_stamps:
        return datetime.datetime.fromtimestamp(pe.header.time_date_stamps)
    else:
        return None


def extract_sig_startdate(pe):
    if pe.has_signature:
        issuer_serial = ":".join(map(lambda e : "{:02x}".format(e), pe.signature.signer_info.issuer[1]))
        for c in pe.signature.certificates:
            serial = ":".join(map(lambda e : "{:02x}".format(e), c.serial_number))
            if serial == issuer_serial:
                d = c.valid_from
                return datetime.datetime(year=d[0], month=d[1], day=d[2], hour=d[3], minute=d[4], second=d[5])
    else:
        return None


def get_sha256(fpath):
    with open(fpath,"rb") as f:
        res = hashlib.sha256(f.read()).hexdigest()
    return res

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Create a timeline of PE/DLL timestamp')
    parser.add_argument('DIRECTORY',  help='an integer for the accumulator')
    parser.add_argument('--recursive', '-r', action='store_true', help='an integer for the accumulator')

    args = parser.parse_args()

    allfiles = {}
    mime = magic.Magic(mime=True)

    if args.recursive:
        for root, dirs, files in os.walk(args.DIRECTORY):
            for f in files:
                fpath = os.path.join(root, f)
                if mime.from_file(fpath) == "application/x-dosexec":
                    pe = lief.parse(fpath)
                    timestamp = extract_datetime(pe)
                    if timestamp is not None:
                        allfiles[timestamp] = ("TIMESTAMP", fpath, get_sha256(fpath))
                    timestamp = extract_sig_startdate(pe)
                    if timestamp is not None:
                        allfiles[timestamp] = ("SIGNATURE", fpath, get_sha256(fpath))
    else:
        for f in os.listdir(args.DIRECTORY):
            fpath = os.path.join(args.DIRECTORY, f)
            if os.path.isfile(fpath):
                if mime.from_file(fpath) == "application/x-dosexec":
                    pe = lief.parse(fpath)
                    timestamp = extract_datetime(pe)
                    if timestamp is not None:
                        allfiles[timestamp] = ("TIMESTAMP", fpath, get_sha256(fpath))
                    timestamp = extract_sig_startdate(pe)
                    if timestamp is not None:
                        allfiles[timestamp] = ("SIGNATURE", fpath, get_sha256(fpath))


    dates = sorted(allfiles.keys())
    for d in dates:
        print("{} - {} - {} - {}".format(d.strftime("%Y-%m-%d %H:%M:%S"), allfiles[d][0], allfiles[d][2], allfiles[d][1]))
