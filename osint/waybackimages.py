#!/usr/bin/env python3
import bs4
import hashlib
import json
import os
import pandas
import pyexifinfo
import requests
import sys
import urllib
import waybackpack
import argparse

# Author :
# Source : http://www.automatingosint.com/blog/2016/12/vacuuming-image-metadata-from-the-wayback-machine/

#
# Searches the Wayback machine for the provided URL
#
def search_archive(url):
    # search for all unique captures for the URL
    results = waybackpack.search(url,uniques_only=True)
    timestamps = []

    # build a list of timestamps for captures
    for snapshot in results:
        timestamps.append(snapshot['timestamp'])

    # request a list of archives for each timestamp
    packed_results = waybackpack.Pack(url,timestamps=timestamps)
    return packed_results

#
# Retrieve the archived page and extract the images from it.
#
def get_image_paths(packed_results):
    images         = []
    count          = 1

    for asset in packed_results.assets:
        # get the location of the archived URL
        archive_url = asset.get_archive_url()
        print("[*] Retrieving %s (%d of %d)" % (archive_url,count,len(packed_results.assets)))

        # grab the HTML from the Wayback machine
        result = asset.fetch()

        # parse out all image tags
        soup = bs4.BeautifulSoup(result)
        image_list = soup.findAll("img")

        # loop over the images and build full URLs out of them
        if len(image_list):
            for image in image_list:
                if not image.attrs['src'].startswith("http"):
                    image_path =  urllib.parse.urljoin(archive_url,image.attrs['src'])
                else:
                    image_path = image.attrs['src']

                if image_path not in images:
                    print("[+] Adding new image: %s" % image_path)
                    images.append(image_path)
        count += 1
    return images

#
# Download the images and extract the EXIF data.
#
def download_images(image_list, url, output_path):
    image_results = []
    image_hashes  = []

    for image in image_list:
        # this filters out images not from our target domain
        if url not in image:
            continue

        try:
            print("[v] Downloading %s" % image)
            response = requests.get(image)
        except:
            print("[!] Failed to download: %s" % image)
            continue

        if "image" in response.headers['content-type']:
            sha1 = hashlib.sha1(response.content).hexdigest()

            if sha1 not in image_hashes:
                image_hashes.append(sha1)
                image_path = os.path.join(output_path,  "%s-%s" % (sha1,image.split("/")[-1]))
                with open(image_path,"wb") as fd:
                    fd.write(response.content)

                print("[*] Saved %s" % image)
                info = pyexifinfo.get_json(image_path)
                info[0]['ImageHash'] = sha1
                image_results.append(info[0])
    return image_results


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Process some urls')
    parser.add_argument('URL', help='URL to look for')
    parser.add_argument('--output', '-o', default='waybackimages',
            help='output folder')
    args = parser.parse_args()

    output_path = os.path.expanduser(args.output)

    if not os.path.exists(output_path):
        os.mkdir(output_path)

    results = search_archive(args.URL)
    print("[*] Retrieved %d possible stored URLs" % len(results.assets))
    image_paths = get_image_paths(results)
    print("[*] Retrieved %d image paths." % len(image_paths))
    image_results = download_images(image_paths, args.URL, output_path)
    # return to JSON and have pandas build a csv
    image_results_json = json.dumps(image_results)
    data_frame = pandas.read_json(image_results_json)
    csv = data_frame.to_csv("results.csv")
    print("[*] Finished writing CSV to results.csv")
