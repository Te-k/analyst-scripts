#!/usr/bin/env python3
import json
import argparse
import networkx as nx

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Generate a Gephi graph based on a json file')
    parser.add_argument('INPUT',  help='INPUT JSON FILE')
    parser.add_argument('OUTPUT', help='Output Gephi file')
    parser.add_argument('--type', '-t', default="all", choices=["all", "followers", "following"],
            help="Type of graph (all, followers, following)")
    args = parser.parse_args()

    # read json file
    f = open(args.INPUT, 'r')
    data = json.load(f)
    f.close()

    # Create graph
    G=nx.DiGraph()
    for user in data:
        ui = data[user]
        # Create user if it does not exist
        if ui["id"] not in G.nodes():
            G.add_node(ui["id"], label=user, name=user)
            G.node[ui["id"]]['viz'] = {'color': {'r': 255, 'g': 0, 'b': 0, 'a': 0}, 'size': 50}
        if args.type in ["all", "followers"]:
            # For each follower
            for f in ui["followers"]:
                if f not in G.nodes():
                    G.add_node(f, label=str(f), name=str(f))
                    G.node[f]['viz'] = { 'size': 1}
                    G.add_edge(f, ui["id"])
                else:
                    G.add_edge(f, ui["id"])
                    G.node[f]['viz']['size'] +=  1
        if args.type in ["all", "following"]:
            # Following
            for f in ui["followings"]:
                if f not in G.nodes():
                    G.add_node(f, label=str(f), name=str(f))
                    G.node[f]['viz'] = { 'size': 1}
                    G.add_edge(ui["id"], f)
                else:
                    G.add_edge(ui["id"], f)
                    G.node[f]['viz']['size'] +=  1

    nx.write_gexf(G, args.OUTPUT)
