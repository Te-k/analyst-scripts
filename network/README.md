# Network scripts

* `check_umbrella.py` : check if domains are in [Cisco Umbrella Top million websites](https://umbrella.cisco.com/blog/cisco-umbrella-1-million)
* `check_ripe_last_route.py` : check last time a BGP route was advertised by an AS using RIPE API
* `checkpoint_banner.py` : get the hostname from a checkpoint firewall admin service
* `cidr_range.py` : print first and last IP address of a CIDR range
* `cidr_reduce.py`: reduce list of IPs in CIDR ranges (IPv4 only so far)
* `extract_iocs.py` : extract potential network indicators from a PCAP file using tshark
* `dns_resolve.py` : resolve domains, results in a CSV file
* `dns_resolve_mx.py` : resolve MX entries from a list of domains
* `list_mullvad_ips.py`: list IPs of mullvad servers
* `test_website.py` : check a domain list and remove those not having a valid website
