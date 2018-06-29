import argparse
import os
import geoip2.database
import matplotlib.pyplot as plt
import cartopy
import cartopy.io.shapereader as shpreader
import cartopy.crs as ccrs
import matplotlib as mpl

"""
Take a list of IPs as an input and create a world map with colors based on the number of IPs per country
"""

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Process some IPs')
    parser.add_argument('FILE', help='File contains IP addresses')
    parser.add_argument('--db', help='GeoIP Country db', default='~/.config/harpoon/GeoLite2-City.mmdb')
    parser.add_argument('--colours', '-c', help='Colours', default='Oranges')
    # See color codes here : https://matplotlib.org/examples/color/colormaps_reference.html
    args = parser.parse_args()

    ipcountries = {}
    db = geoip2.database.Reader(os.path.expanduser(args.db))

    with open(args.FILE, 'r') as f:
        data = f.read().split('\n')

    for ip in data:
        if ip != '':
            res = db.city(ip)
        if res.country.iso_code in ipcountries:
            ipcountries[res.country.iso_code] += 1
        else:
            ipcountries[res.country.iso_code] = 1

    # Inspired by this https://jekel.me/2016/Population-Density-Plots/
    fig, ax = plt.subplots(figsize=(1,1), subplot_kw={'projection': ccrs.PlateCarree()})
    ax.add_feature(cartopy.feature.LAND)
    #ax.add_feature(cartopy.feature.OCEAN)
    ax.add_feature(cartopy.feature.COASTLINE)
    ax.add_feature(cartopy.feature.BORDERS)
    #ax.add_feature(cartopy.feature.LAKES, alpha=0.95)
    #ax.add_feature(cartopy.feature.RIVERS)
    #ax.set_extent([-150, 60, -25, 60])
    #ax.set_extent([-150, 60, -25, 60])

    # Color map
    cmap = plt.get_cmap(args.colours)
    norm = mpl.colors.Normalize(vmin=0, vmax=max(ipcountries.values()))

    shpfilename = shpreader.natural_earth(resolution='110m',
                    category='cultural',
                    name='admin_0_countries')
    reader = shpreader.Reader(shpfilename)
    countries = reader.records()
    for country in countries:
        if country.attributes['ISO_A2'] in ipcountries:
            ax.add_geometries(country.geometry, ccrs.PlateCarree(),
                    facecolor=cmap(norm(ipcountries[country.attributes['ISO_A2']])),
                    linewidth=0.01)
        else:
            ax.add_geometries(country.geometry, ccrs.PlateCarree(),
                        facecolor=cmap(norm(0)),
                        linewidth=0.01)

    #ax.set_title('Title')
    cax = fig.add_axes([0.95, 0.2, 0.02, 0.6])
    cb = mpl.colorbar.ColorbarBase(cax, cmap=cmap, norm=norm, spacing='proportional', format='%.0f')
    plt.show()






