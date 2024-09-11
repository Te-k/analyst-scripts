import ipaddress
import argparse

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Reduce IPs into IP ranges from a file"
    )
    parser.add_argument("FILE", help="File containing list of IP addresses")
    args = parser.parse_args()

    with open(args.FILE, "r") as f:
        data = list(set([d.strip() for d in f.read().split()]))

    res = []
    entries = sorted(data)
    while len(entries) != 0:
        ip = entries.pop()
        ipp = ipaddress.ip_address(ip)
        if ipp.version != 4:
            print("{} is not an IPv4 address, skipping".format(ip))
            continue
        cidr = 32
        cidr_found = False
        while not cidr_found:
            potential_net = ipaddress.ip_network("{}/{}".format(ip, cidr), False)
            print(potential_net)
            for host in potential_net.hosts():
                if str(host) != ip and str(host) not in entries:
                    cidr_found = True
                    cidr += 1
                    break
            cidr -= 1
        network = ipaddress.ip_network("{}/{}".format(ip, cidr), False)
        for host in network.hosts():
            if str(host) in entries:
                entries.remove(str(host))

        res.append(str(network))

    for entry in sorted(res):
        print(entry)
