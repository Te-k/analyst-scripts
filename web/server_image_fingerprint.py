#! /usr/bin/env python2
import urllib2
import urlparse
import argparse
import os

data = {
        "Apache":"/icons/apache_pb.gif",
        "Apache 2.x":"/icons/apache_pb2.gif",
        "Microsoft IIS 7.x":"/welcome.png",
        "Microsoft IIS":"/pagerror.gif",
        "QNAP NAS":"/ajax_obj/img/running.gif",
        "QNAP NAS_":"/ajax_obj/images/qnap_logo_w.gif",
        "Belkin Router":"/images/title_2.gif",
        "Billion Router":"/customized/logo.gif",
        "Linksys NAS":"/Admin_top.JPG",
        "Linksys NAS_":"/logo.jpg",
        "Linksys Network Camera":"/welcome.jpg",
        "Linksys Wireless-G Camera":"/header.gif",
        "Cisco IP Phone":"/Images/Logo",
        "Snom Phone":"/img/snom_logo.png",
        "Dell Laser Printer":"/ews/images/delllogo.gif",
        "Brother Printer":"/pbio/brother.gif",
        "HP LaserJet Printer":"/hp/device/images/logo.gif",
        "HP LaserJet Printer_":"/hp/device/images/hp_invent_logo.gif",
        "JBoss Application server":"/images/logo.gif",
        "APC InfraStruXure Manager":"/images/Xlogo_Layer-1.gif",
        "Barracuda Spam/Virus Firewall":"/images/powered_by.gif",
        "TwonkyMedia Server":"/images/TwonkyMediaServer_logo.jpg",
        "VMware ESXi Server":"/background.jpeg",
        "Microsoft Remote Web Workplace":"/Remote/images/submit.gif",
        "XAMPP":"/xampp/img/xampp-logo-new.gif",
        "Xerox Printer":"/printbut.gif",
        "Konica Minolta Printer":"/G27_light.gif",
        "Epson Printer":"/cyandot.gif",
        "HP Printer":"/hp/device/images/hp_invent_logo.gif",
        "Zenoss":"/zport/dmd/favicon.ico",
        "BeEF":"/ui/media/images/beef.png",
        "BeEF (PHP)":"/beef/images/beef.gif",
        "Wordpress":"/wp-includes/images/wpmini-blue.png",
        "Glassfish Server":"/theme/com/sun/webui/jsf/suntheme/images/login/gradlogsides.jpg",
        "pfSense":"/themes/pfsense_ng/images/logo.gif",
        "m0n0wall":"/logo.gif"
        }
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Fingerprint the web browser with specific image files')
    parser.add_argument('-v', '--verbose', help='Verbose mode', action='store_true')
    parser.add_argument('host', metavar='HOST',  help='Host targeted')

    args = parser.parse_args()

    if not args.host.startswith("http"):
        host = "http://" + args.host
        hostname = args.host
    else:
        host = args.host
        hostname = urlparse.urlparse(args.host).netloc

    # Check host validity
    req = urllib2.Request(host)
    try:
        r = urllib2.urlopen(req)
        if r.getcode() != 200:
            print "Host unavailable!"
            exit(1)
    except urllib2.URLError as e:
        print "Host unavailable!"
        exit(1)

    print " -> Look for known pictures to fingerprint the web server/framework"
    print " %i images in the database\n" % len(data)
    found = False

    for key in data.keys():
        req = urllib2.Request(urlparse.urljoin(host, data[key]))
        try:
            resp = urllib2.urlopen(req)
            if resp.getcode() == 200:
                found = True
                print "%s found ! (%s)" % (key, data[key])
        except urllib2.HTTPError as e:
            if args.verbose:
                print "XXX %s not found (server: %s)" % (data[key], key)

    if not found:
        print "Nothing found!"
