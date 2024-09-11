import argparse
import os
import sys
import pytz
from collections import Counter


def bracket(domain: str) -> str:
    """Add protective bracket to a domain"""
    last_dot = domain.rfind(".")
    return domain[:last_dot] + "[.]" + domain[last_dot + 1 :]


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Makes a timeline out of list of domains"
    )
    parser.add_argument(
        "--output",
        "-o",
        help="If provided, also creates images for timezones and days of the week",
    )
    parser.add_argument(
        "--format", "-f", choices=["txt", "md"], default="md", help="Output format"
    )
    parser.add_argument(
        "--timezone",
        "-t",
        choices=pytz.all_timezones,
        default="UTC",
        help="Timezone (pytz formqt, default is UTC)",
    )
    parser.add_argument("FILE", help="File containing a list of domains")
    args = parser.parse_args()
    try:
        import whois
    except ModuleNotFoundError:
        print("python-whois not installed")
        print("pip install python-whois is what you need")
        print("quitting")
        sys.exit(1)

    if not os.path.isfile(args.FILE):
        print("Can't open the file, quitting")
        sys.exit(1)

    tz = pytz.timezone(args.timezone)
    utc = pytz.timezone("UTC")

    with open(args.FILE) as f:
        domains = f.read().split()

    print(
        "This script is assuming any whois timezone is UTC, which may not always be accurate"
    )

    try:
        domains.remove("")
    except ValueError:
        pass

    results = []
    for d in domains:
        w = whois.whois(d)
        res = {"domain": d, "registrar": w.registrar}
        # Creation date
        if isinstance(w.creation_date, list):
            creation_date = w.creation_date[0]
        else:
            creation_date = w.creation_date
        # Convert to the right timezone
        creation_date = utc.localize(creation_date)
        res["creation_date"] = creation_date

        if w.update_date:
            if isinstance(w.update_date, list):
                update_date = w.update_date[0]
            else:
                update_date = w.update_date
            update_date = utc.localize(update_date)

            res["update_date"] = update_date

        results.append(res)

    print("Timeline in UTC:")
    if args.format == "md":
        print("| Date | Event |")
        print("|------|-------|")

    for d in sorted(results, key=lambda x: x["creation_date"]):
        if args.format == "txt":
            print(
                "{}: registration of {}".format(
                    d["creation_date"].isoformat(), bracket(d["domain"])
                )
            )
        else:
            print(
                "| {} | Registration of `{}` |".format(
                    d["creation_date"].isoformat(), d["domain"]
                )
            )

    registrars = Counter([a["registrar"] for a in results])
    print("")
    print("Registrars:")
    for entry in registrars:
        print("-{} : {} domains".format(entry, registrars[entry]))

    if args.output:
        if not os.path.isdir(args.output):
            print("Please provide a folder for the output")
            sys.exit(1)

        # Start with results
        if args.format == "txt":
            fout = open(os.path.join(args.output, "timeline.txt"), "w")
            for d in sorted(results, key=lambda x: x["creation_date"]):
                fout.write(
                    "{}: registration of `{}`\n".format(
                        d["creation_date"].isoformat(), bracket(d["domain"])
                    )
                )
            print("Timeline written in timeline.txt")
        else:
            fout = open(os.path.join(args.output, "timeline.md"), "w")
            fout.write("| Date | Event |\n")
            fout.write("|------|-------|\n")
            for d in sorted(results, key=lambda x: x["creation_date"]):
                fout.write(
                    "| {} | registration of {}|\n".format(
                        d["creation_date"].isoformat(), d["domain"]
                    )
                )
            print("Timeline written in timeline.md")

        try:
            import matplotlib.pyplot as plt
        except ModuleNotFoundError:
            print("Matplotlib not found, no figure will be generated")
            sys.exit(0)

        # Time of the day
        time_of_day = {}
        for i in range(24):
            time_of_day[i] = 0
        for entry in results:
            creation_date = entry["creation_date"].astimezone(tz)
            time_of_day[creation_date.hour] += 1
            if "update_date" in entry:
                update_date = entry["update_date"].astimezone(tz)
                time_of_day[update_date.hour] += 1

        days = list(range(24))
        values = list(time_of_day.values())

        fig = plt.figure(figsize=(10, 5))

        # creating the bar plot
        plt.bar(days, values)
        plt.xlabel("Hours of the day")
        plt.ylabel("Domain events")
        plt.title("Domain events per hour in {} timezone".format(tz.zone))
        plt.savefig(os.path.join(args.output, "timezone.png"))
        plt.show()

        # Day of the week
        days = {}
        for i in range(7):
            days[i] = 0

        for entry in results:
            creation_date = entry["creation_date"].astimezone(tz)
            days[creation_date.weekday()] += 1
            if "update_date" in entry:
                update_date = entry["update_date"].astimezone(tz)
                days[update_date.weekday()] += 1

        ddays = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
        values = list(days.values())

        fig = plt.figure(figsize=(10, 5))

        # creating the bar plot
        plt.bar(ddays, values)
        plt.xlabel("Days of the week")
        plt.ylabel("Domain events")
        plt.title("Domain events per day of the week ({} timezone)".format(tz.zone))
        plt.savefig(os.path.join(args.output, "weekday.png"))
        plt.show()
