import argparse
import json
import networkx as nx


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Convert dexofuzzy output to gephi graph')
    parser.add_argument('JSONFILE', help='Json file')
    args = parser.parse_args()

    with open(args.JSONFILE, 'r') as f:
        data = json.loads(f.read())

    G = nx.Graph()
    for s in data:
        # Add node
        if not G.has_node(s['file_sha256']):
            G.add_node(s['file_sha256'])
        # Add cluster
        for c in s['clustering']:
            if s['file_sha256'] != c['file_sha256']:
                # Add node
                if not G.has_node(c['file_sha256']):
                    G.add_node(c['file_sha256'])
                if not G.has_edge(s['file_sha256'], c['file_sha256']):
                    G.add_edge(s['file_sha256'], c['file_sha256'])

    nx.write_gexf(G, 'output.gexf')
    print("Gephi file written : output.gexf")
