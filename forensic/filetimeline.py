#!/usr/bin/env python
import os
import sys
import argparse


def get_stat(file_path):
    """
    Get stat information from a filepath
    Returns (PATH, SIZE, Access Time, Modification Time, Change Time, uid, gid, access rights)
    """
    stat = os.stat(file_path)
    return [
            file_path,
            stat.st_size,
            stat.st_atime,
            stat.st_mtime,
            stat.st_ctime,
            stat.st_uid,
            stat.st_gid,
            oct(stat.st_mode)
    ]


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Create a timeline of files')
    parser.add_argument('PATH', help='Path of the folder to create the timeline')
    parser.add_argument('--output', '-o', help='Output file path')
    args = parser.parse_args()

    if not os.path.exists(args.PATH):
        print("Directory does not exist")
        sys.exit(1)

    fout = open(args.output, "a+")
    fout.write("|".join(["Path", "Size", "Access Time", "Modification Time", "Change Time", "uid", "gid", "access rights"]) + "\n")

    count = 0
    for root, dirs, files in os.walk(args.PATH):
        for name in files:
            infos = get_stat(os.path.join(root, name))
            fout.write("|".join([str(a) for a in infos]) + "\n")
            count += 1

    fout.close()

    print("Information on %i files stored in %s" % (count, args.output))
