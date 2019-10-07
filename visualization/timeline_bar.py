#!/usr/bin/env python3
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import argparse

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Process a timeline')
    parser.add_argument('FILE', help='CSV file')
    args = parser.parse_args()


    # Read file
    df = pd.read_csv(args.FILE)
    c1_date = df.columns[0]
    c2_type = df.columns[1]
    # List the different types
    types = df[c2_type].unique()

    # Convert the first column to datetime
    df['day'] = pd.to_datetime(df[c1_date])
    mint = df['day'].min()
    maxt = df['day'].max()
    df = df.set_index('day')

    #dg = df.groupby([df.day.dt.year, df.day.dt.month, c2_type]).count()
    data = {'months': pd.period_range(mint, maxt, freq='M')}
    for d in types:
        dg = df[(df[c2_type] == d)]
        dg2 = dg.groupby(dg.index.to_period('M')).count()
        data[d] = dg2.reindex(pd.period_range(mint, maxt, freq='M'))[c2_type].values


    dff = pd.DataFrame(data)

    ax = dff.set_index('months').plot(kind='bar')
    ax.set_xticklabels(dff['months'].dt.strftime('%b, %Y'))
    plt.xticks(rotation=70)
    plt.show()
