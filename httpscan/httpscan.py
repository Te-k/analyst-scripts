#!/usr/bin/env python2
# -*- coding: utf-8 -*-
import requests
import argparse
from urlparse import urljoin



class Scanner(object):
    def __init__(self, targets, verbose=0):
        self.targets = targets
        self.verbose = verbose
        self.ua = "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1"
        self.interesting_files = [
                '.git',
                '.svn',
                '.htaccess',
                '.log',
                'log.txt',
                'log',
                'logs',
                'logs.txt',
                'index.html',
                '.well-known'
        ]

        # list gathered from https://github.com/0xd34db33f/scriptsaw/blob/master/ruby/phish_kit_finder.rb
        self.phishing_kits = ['dropbox.zip','sparskss.zip','dpbx.zip','wells3x.zip','secureLogin_3.zip','administrator.zip','ipaad.zip','msn.zip','wellsfargo.zip','bookmark.zip','Dropbox.zip','www.zip','hotmail.zip','update.zip','xnowxoffnowxnowoffhd.zip','global.zip','docx.zip','support-Verification.zip','estatspark.zip','login.zip','ipad.zip','scampage.zip','s.p.zip','Arch.zip','filez.zip','irs.zip','gdoc.zip','phone.zip','nD.zip','db.zip','adobe.zip','FOX.zip','usaa.zip','GD.zip','itunes.appel.com.zip','DROPBOX%20MEN..zip','BDB.zip','yahoo.zip','update_info-paypal-tema-login-update_info-paypal-tema-login-update_info-paypal-tema-loginhome.zip','outlook.zip','icscards:nl.zip','googledocs.zip','alibaba.zip','www.kantonalbank.ch.zip','wes.zip','google.zip','Zone1.zip','BDBB.zip','Aol-Login.zip','live.com.zip','gmail.zip','drpbx%20-%20Copy.zip','Google.zip','GD1.zip','BiyiBlaze.zip','BDBBB4.zip','Aolnew.zip','wells.zip','web.zip','validation.zip','usaa_com.zip','servelet_usaa.zip','order.zip','home.zip','document.zip','chase.zip','app.zip','BOBI.zip','maxe.zip','max.zip','googledrive.zip','googledoc.zip','general.zip','filedrop.zip','dr.zip','doc.zip','access.zip','Yahoo.zip','Yahoo-2014.zip','DropBoxDocument.zip','www.hypovereinsbank.de.zip','www.citibank.com.my.zip','undoo.zip','tesco.zip','spass.zip','outlook%20True..zip','myposte.zip','hvsf.zip','gmez.zip','global2.zip','dpp.zip','Usaa.zip','R-viewdoc.zip','Pamilerinayooluwa.zip','Ourtime.zip','Hotmail-New.zip','DHL.zip','Adobe.zip','wp-admin.zip','westpac.zip','wellsfargo.com.zip','welcome.zip','suite.zip','spaskas.zip','signontax.zip','share.zip','script1.zip','santander.zip','rr.zip','online.zip','new.zip','new%20google%20doc..zip','dropboxLanre.zip','drive.zip','docs.zip','db2.zip','christain_mingle.zip','aol.zip','Investor.zip','G6.zip','BILLIONS%20PAGE..zip','yahoo.com.zip','ww.zip','ups.zip','outlooknew.zip','finance.zip','files.zip','dropbox1..zip','dropbox%20LoginVerification%20-prntscr.com-9sjlf0.zip','dhl.zip','db2016.zip','css.zip','commbankonlineau.zip','box.zip','bof.zip','bbooffaa.zip','auth.inet.ent_Logon-redirectjsp.true.zip','art.zip','admin.zip','accounts.zip','LIFEVERIFY.zip','IRS.zip','GOG.zip','Dropbox1..zip','Doc.zip','DROPBOX','Business.zip','8-login-form.zip','1.zip','wllxzccc.zip','webmail.zip','vivt.zip','validate.zip','spar.zip','royalbank.zip','review.zip','rebuilt.gdoc.zip','obiora.zip','news.zip','match2.zip','maildoc.zip','google%20dariver%202015.zip','good.zip','gee.zip','dropelv.%20-%20Copy.zip','dropbox2016.zip','dropbl.zip','dpx.zip','dm.zip','db2011.zip','class.zip','ch.zip','capitalone360.zip','apple.zip','aoljunior.zip','PDP..zip','Nuvo.zip','Newdropbox15-1.zip','Gouv_lmpouts.zip','Gmail.zip','Gdoc.zip','Fresh.zip','Ed.zip','DROPBOX.zip','3.0.zip','gdocs.zip','gdocs1.zip','GD.zip','art3..zip']

    def _request(self, server, path):
        headers = {'user-agent': self.ua}
        if not server.startswith("http://"):
            server = "http://" + server
        try:
            res = requests.get(
                    urljoin(server, path),
                    headers=headers,
                    timeout=0.5,
                    verify=False
                    )
        except requests.exceptions.ConnectionError:
            return False, None, "%s -> Connection Error" % server
        except requests.exceptions.ReadTimeout:
            return False, None,"%s -> Connection timeout" % server
        except requests.exceptions.TooManyRedirects:
            return False, None, "%s -> Too many redirects" % server
        else:
            return True, res, ''

    def analyse_headers(self, headers):
        """
        Analyze HTTP response headers
        """
        infos = {}
        for header in ['Server', 'Last-Modified']:
            if header in headers:
                infos[header] = headers[header]
        return infos

    def scan_page(self, path):
        """
        Temp function, san one page and prin results
        """
        for server in self.targets:
            success, res, error = self._request(server, path)
            if success:
                print("%s -> %i" % (server, res.status_code))
            else:
                print(error)

    def default_scan_host(self, target, tls=False):
        """
        Scan one host with default scan
        """
        if tls:
            if "http://" in target:
                target = target.replace("http", "https")
        success, res, error = self._request(target, "/")
        if success:
            if tls:
                print("\tHTTPs / %i %s" % (res.status_code, res.reason))
            else:
                print("\tHTTP / %i %s" % (res.status_code, res.reason))
            # Check headers
            if self.verbose > 1:
                print("\tHeaders:")
                for h in res.headers:
                    print("\t\t%s: %s" % (h, res.headers[h]))
            else:
                headers = self.analyse_headers(res.headers)
                if len(headers) > 0:
                    print("\tInteresting headers:")
                    for i in headers:
                        print("\t\t-%s: %s" % (i, headers[i]))
            # Check content of the page
            # TODO
            return success, res
        else:
            print("\tRequest on /: %s" % error)
            return success, res

    def check_files(self, target, path="/", phishing=False):
        """
        Look for interesting files on the server
        """
        print("\tTesting interesting files")

        for f in self.interesting_files:
            success, res, error = self._request(target, urljoin(path, f))
            if success and res.status_code != 404:
                print("\t\t %s found (%i)" % (f, res.status_code))

    def default_scan(self):
        """
        Default scan includes request on / and gathering of information
        """
        for server in self.targets:
            print("Scanning: %s" % server)
            success, res = self.default_scan_host(server)
            success, res = self.default_scan_host(server, tls=True)


    def phishing_scan(self, path):
        """
        Phishing scan : default scan + check phishing kits
        """
        for server in self.targets:
            print("Scanning: %s" % server)
            success, res = self.default_scan_host(server)
            if success:
                # Check interesting files
                self.check_files(server, path, phishing=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Scan HTTP server check for a file')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--server', '-s', help="Server to check")
    group.add_argument('--file', '-f', help="File containing list of IP/domains")
    parser.add_argument('-v', '--verbose', action='count', default=0)
    parser.add_argument('--default', '-d', action='store_true', help='Default scan')
    parser.add_argument('--path', '-p', help='Request a specific path')
    parser.add_argument('--phishing', '-P', help='Phishing Scan')
    args = parser.parse_args()

    if args.server is not None:
        target = [args.server]
    elif args.file is not None:
        f = open(args.file, "r")
        servers = f.read().split("\n")
        target = filter(lambda x: x != '', map(lambda x:x.strip(), servers))
        f.close()
    else:
        print("You need to provide a target")
        parser.print_help()
        sys.exit(0)

    scanner = Scanner(target, args.verbose)
    if args.path:
        scanner.scan_page(args.path)
    elif args.phishing:
        res = scanner.phishing_scan(args.phishing)
    else:
        res = scanner.default_scan()
