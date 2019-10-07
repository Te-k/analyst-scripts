#!/usr/bin/env python3
import numpy as np;
import pandas as pd
import calmap # Use my fork https://github.com/Te-k/calmap
import matplotlib.pyplot as plt
import argparse

# references
# https://pythonhosted.org/calmap/

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Create a heatmap based on csv file')
    parser.add_argument('FILE', help='Csv file, like 2018-07-01;1 for 1 incident that day')
    parser.add_argument('--sep', '-s', default=';',
        help='Separator for the csv file (default is ;)')
    args = parser.parse_args()

    df=pd.read_csv(args.FILE, sep=args.sep,header=None)
    dates = pd.to_datetime(df[0])
    events = pd.Series(np.array(df[1]), index=dates)
    calmap.yearplot(events, year=min(dates).year)
    plt.show()
