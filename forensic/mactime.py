#!/usr/bin/env python3
import argparse
from datetime import datetime


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Convert raw extraction from filetimeline.py into a nice timeline')
    parser.add_argument('FILE', help='an integer for the accumulator')
    parser.add_argument('--output', '-o', default="timeline.txt",
            help='Output file')
    parser.add_argument('--no-access', '-n', action='store_true',
            help="Do not consider access time")
    args = parser.parse_args()

    out = []
    with open(args.FILE, 'r', errors='replace') as fin:
        data = fin.read().split("\n")

    for d in data[1:]:
        if d.strip() == "":
            break
        dd = d.split("|")
        if args.no_access:
            if dd[3] == dd[4]:
                out.append({
                    "file": dd[0],
                    "type": "m.c",
                    "date": datetime.fromtimestamp(float(dd[3])),
                    "uid": dd[5],
                    "size": dd[1]
                })
            else:
                out.append({
                    "file": dd[0],
                    "type": "m..",
                    "date": datetime.fromtimestamp(float(dd[3])),
                    "uid": dd[5],
                    "size": dd[1]
                })
                out.append({
                    "file": dd[0],
                    "type": "..c",
                    "date": datetime.fromtimestamp(float(dd[4])),
                    "uid": dd[5],
                    "size": dd[1]
                })
        else:
            if dd[2] == dd[3]:
                if dd[2] == dd[4]:
                    out.append({
                        "file": dd[0],
                        "type": "mac",
                        "date": datetime.fromtimestamp(float(dd[2])),
                        "uid": dd[5],
                        "size": dd[1]
                    })
                else:
                    # ATIME == MTIME. CTIME is different
                    out.append({
                        "file": dd[0],
                        "type": "ma.",
                        "date": datetime.fromtimestamp(float(dd[2])),
                        "uid": dd[5],
                        "size": dd[1]
                    })
                    out.append({
                        "file": dd[0],
                        "type": "..c",
                        "date": datetime.fromtimestamp(float(dd[4])),
                        "uid": dd[5],
                        "size": dd[1]
                    })
            else:
                if dd[2] == dd[4]:
                    # ATIME == CTIME, MTIME is different
                    out.append({
                        "file": dd[0],
                        "type": ".ac",
                        "date": datetime.fromtimestamp(float(dd[2])),
                        "uid": dd[5],
                        "size": dd[1]
                    })
                    out.append({
                        "file": dd[0],
                        "type": "m..",
                        "date": datetime.fromtimestamp(float(dd[3])),
                        "uid": dd[5],
                        "size": dd[1]
                    })
                else:
                    if dd[3] == dd[4]:
                        # CTIME == MTIME, ATIME is different
                        out.append({
                            "file": dd[0],
                            "type": "m.c",
                            "date": datetime.fromtimestamp(float(dd[3])),
                            "uid": dd[5],
                            "size": dd[1]
                        })
                        out.append({
                            "file": dd[0],
                            "type": ".a.",
                            "date": datetime.fromtimestamp(float(dd[2])),
                            "uid": dd[5],
                            "size": dd[1]
                        })
                    else:
                        # ALL DIFFERENT
                        out.append({
                            "file": dd[0],
                            "type": "m..",
                            "date": datetime.fromtimestamp(float(dd[3])),
                            "uid": dd[5],
                            "size": dd[1]
                        })
                        out.append({
                            "file": dd[0],
                            "type": ".a.",
                            "date": datetime.fromtimestamp(float(dd[2])),
                            "uid": dd[5],
                            "size": dd[1]
                        })
                        out.append({
                            "file": dd[0],
                            "type": "..c",
                            "date": datetime.fromtimestamp(float(dd[4])),
                            "uid": dd[5],
                            "size": dd[1]
                        })

    # Write output
    fout = open(args.output, "a+")
    fout.write("|".join(["Date", "Type", "Size", "UID", "Path"]) + "\n")
    for entry in sorted(out, key=lambda x: x["date"]):
        fout.write(" | ".join([entry["date"].isoformat()[:19], entry["type"], entry["size"], entry["uid"], entry["file"]]) + "\n")
    print("%i entries written in %s" % (len(out), args.output))
