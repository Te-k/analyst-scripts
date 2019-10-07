#!/usr/bin/env python3
import argparse
import os
import geoip2.database
import matplotlib.pyplot as plt
import cartopy
import cartopy.io.shapereader as shpreader
import cartopy.crs as ccrs
import matplotlib as mpl
from iso3166 import countries
try:
    import plotly.plotly as py
    plotly = True
except ImportError:
    plotly = False

"""
Take a list of IPs as an input and create a world map with colors based on the number of IPs per country
"""

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Process some IPs')
    parser.add_argument('FILE', help='File contains IP addresses')
    parser.add_argument('--data', '-d', action='store_true',
            help='Print of csv of count per countries')
    parser.add_argument('--plotly', '-p', action='store_true',
            help='Plot with plot.ly')
    parser.add_argument('--db', help='GeoIP Country db', default='~/.config/harpoon/GeoLite2-City.mmdb')
    parser.add_argument('--colours', '-c', help='Colours', default='Oranges')
    # See color codes here : https://matplotlib.org/examples/color/colormaps_reference.html
    args = parser.parse_args()

    ipcountries = {}
    for c in countries:
        ipcountries[c.alpha2] = {
            'name': c.name,
            'code': c.alpha2,
            'code3': c.alpha3,
            'count': 0
        }

    db = geoip2.database.Reader(os.path.expanduser(args.db))

    with open(args.FILE, 'r') as f:
        data = f.read().split('\n')

    for ip in data:
        try:
            if ip != '':
                res = db.city(ip)
            ipcountries[res.country.iso_code]['count'] += 1
        except geoip2.errors.AddressNotFoundError:
            pass

    if args.data:
        print('country,code,code3,count')
        for ip in sorted(ipcountries.values(), key=lambda x: x['count'], reverse=True):
            print('%s,%s,%s,%s' % (
                    ip['name'],
                    ip['code'],
                    ip['code3'],
                    ip['count']
                )
            )
    elif args.plotly:
        if plotly:
            # Inspired by https://plot.ly/python/choropleth-maps/
            data = [ dict(
                type = 'choropleth',
                locations = [b['code3'] for b in ipcountries.values()],
                z = [b['count'] for b in ipcountries.values()],
                text = [b['name'] for b in ipcountries.values()],
                colorscale = [[0,"rgb(5, 10, 172)"],[0.35,"rgb(40, 60, 190)"],[0.5,"rgb(70, 100, 245)"],\
                [0.6,"rgb(90, 120, 245)"],[0.7,"rgb(106, 137, 247)"],[1,"rgb(220, 220, 220)"]],
                autocolorscale = False,
                reversescale = True,
                marker = dict(
                line = dict (
                    color = 'rgb(180,180,180)',
                    width = 0.5
                ) ),
                colorbar = dict(
                    autotick = False,
                ),
            ) ]
            layout = dict(
                geo = dict(
                    showframe = False,
                    showcoastlines = False,
                    projection = dict(
                    type = 'Mercator' # Would be cool to allow other projections http://etpinard.xyz/plotly-dashboards/map-projections/
                    )
                )
            )
            fig = dict( data=data, layout=layout )
            py.plot( fig, validate=False, filename=args.plotly)
        else:
            print('Please install plot.ly first')

    else:
        # Inspired by this https://jekel.me/2016/Population-Density-Plots/
        fig, ax = plt.subplots(figsize=(1,1), subplot_kw={'projection': ccrs.PlateCarree()})
        ax.add_feature(cartopy.feature.LAND)
        ax.add_feature(cartopy.feature.COASTLINE)
        ax.add_feature(cartopy.feature.BORDERS)

        # Color map
        cmap = plt.get_cmap(args.colours)
        norm = mpl.colors.Normalize(vmin=0, vmax=max([a['count'] for a in ipcountries.values()]))

        shpfilename = shpreader.natural_earth(resolution='110m',
                    category='cultural',
                    name='admin_0_countries')
        reader = shpreader.Reader(shpfilename)
        countries = reader.records()
        for country in countries:
            if country.attributes['ISO_A2'] in ipcountries:
                ax.add_geometries(country.geometry, ccrs.PlateCarree(),
                        facecolor=cmap(norm(ipcountries[country.attributes['ISO_A2']]['count'])),
                        linewidth=0.01)
            else:
                ax.add_geometries(country.geometry, ccrs.PlateCarree(),
                            facecolor=cmap(norm(0)),
                            linewidth=0.01)

        #ax.set_title('Title')
        cax = fig.add_axes([0.95, 0.2, 0.02, 0.6])
        cb = mpl.colorbar.ColorbarBase(cax, cmap=cmap, norm=norm, spacing='proportional', format='%.0f')
        plt.show()
