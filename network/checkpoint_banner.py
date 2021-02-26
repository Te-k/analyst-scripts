import socket
import argparse
import os

def check_ip(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(10)
            s.connect((ip, port))
            s.sendall(b"\x51\x00\x00\x00\x00\x00\x00\x21")
            data = s.recv(4)
            if data and data == b"Y\x00\x00\x00":
                #print("Checkpoint Firewall")
                s.sendall(b"\x00\x00\x00\x0bsecuremote\x00")
                data = s.recv(200)
                return data[4:-8].strip(b"\x00").decode('utf-8').split(",")
    except socket.timeout:
        return None
    except ConnectionRefusedError:
        return None
    except OSError:
        return None
    return None

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Extract Checkpoint Banner')
    subparsers = parser.add_subparsers(help='subcommand')
    parser_a = subparsers.add_parser("ip")
    parser_a.add_argument('IP', help='IP address')
    parser_a.add_argument('--port', '-p', type=int, default=264, help='Port')
    parser_a.set_defaults(subcommand='ip')
    parser_b = subparsers.add_parser("list")
    parser_b.add_argument('FILE', help='List of IP addresses')
    parser_b.add_argument('--port', '-p', type=int, default=264, help='Port')
    parser_b.set_defaults(subcommand='list')
    args = parser.parse_args()

    if 'subcommand' in args:
        if args.subcommand == 'ip':
            print(check_ip(args.IP, args.port))
        elif args.subcommand == 'list':
            with open(args.FILE) as f:
                data = f.read().split('\n')
            for ip in data:
                if ip.strip() == "":
                    continue
                info = check_ip(ip, args.port)
                if info:
                    print("{} - {} - {}".format(ip, info[0], info[1]))
                else:
                    print("{} - No data".format(ip))
        else:
            parser.print_help()
    else:
        parser.print_help()


