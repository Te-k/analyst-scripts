import configparser
import os
from pathlib import Path
from censys.search import CensysHosts
import argparse

config_path = os.path.join(str(Path.home()), ".config", "censys", "censys.cfg")

def get_config() -> configparser.ConfigParser:
    """Reads and returns config.
    Returns:
        configparser.ConfigParser: Config for Censys.
    """
    config = configparser.ConfigParser()
    if os.path.isfile(config_path):
        config.read(config_path)
    else:
        print("Config not found")
    return config


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Make censys IP search')
    parser.add_argument('QUERY', help="Censys query")
    args = parser.parse_args()

    h = CensysHosts()

    query = h.search(args.QUERY, per_page=100)
    for r in query():
        print(r['ip'])


