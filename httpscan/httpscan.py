#!/usr/bin/env python2
# -*- coding: utf-8 -*-
import argparse
import ssl
import sys
import os
import logging
from urlparse import urljoin
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from bs4 import BeautifulSoup
import yaml
import requests


class Signature(object):
    """
    Class for signature of phishing kits
    """
    def __init__(self, data, scanner):
        # TODO: implement a rule format checker
        self.name = data.keys()[0]
        self.tests = data[self.name]['tests']
        self.condition = data[self.name]['condition']
        self._scanner = scanner

    def run_test(self, target, test):
        """
        Run one test on a target
        :returns True/False
        """
        success, res, error = self._scanner._request(target, test['path'])
        if success:
            if 'content' in test.keys():
                if test['content'] not in res.text:
                    return False
            if 'code' in test.keys():
                if res.status_code != test['code']:
                    return False
            return True
        else:
            return False

    def run(self, target):
        """
        Run the tests on the target and return True / False
        """
        if self.condition == 'all':
            for test in self.tests:
                res = self.run_test(target, test)
                if not res:
                    return False
            return True
        else:
            # condition any
            for test in self.tests:
                res = self.run_test(target, test)
                if res:
                    return True
            return False


class Scanner(object):
    def __init__(self, targets, verbose=0, output=None):
        self.targets = targets
        self.verbose = verbose
        self.useragent = "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1"
        self.sigdir = os.path.join(
            os.path.dirname(os.path.realpath(__file__)),
            "signatures"
        )
        self.signatures = None
        self.output = output
        self.log = logging.getLogger('httpscan')

        if verbose > 2:
            self.logging_level = logging.DEBUG
        else:
            self.logging_level=[logging.WARNING, logging.INFO, logging.DEBUG][verbose]

        self.log.setLevel(self.logging_level)
        ch = logging.StreamHandler()
        ch.setLevel(self.logging_level)
        ch.setFormatter(logging.Formatter('%(message)s'))
        self.log.addHandler(ch)

        if self.output:
            fh = logging.FileHandler(os.path.join(self.output, 'scan.log'))
            fh.setLevel(self.logging_level)
            fh.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
            self.log.addHandler(fh)

        self.interesting_files = [
            '.git',
            '.gitignore',
            '.svn',
            '.htaccess',
            '.log',
            'log.txt',
            'log',
            'logs',
            'logs.txt',
            'index.html',
            '.well-known',
            '/static/'
        ]

        # list gathered from https://github.com/0xd34db33f/scriptsaw/blob/master/ruby/phish_kit_finder.rb
        self.phishing_kits = ['dropbox.zip','sparskss.zip','dpbx.zip','wells3x.zip','secureLogin_3.zip','administrator.zip','ipaad.zip','msn.zip','wellsfargo.zip','bookmark.zip','Dropbox.zip','www.zip','hotmail.zip','update.zip','xnowxoffnowxnowoffhd.zip','global.zip','docx.zip','support-Verification.zip','estatspark.zip','login.zip','ipad.zip','scampage.zip','s.p.zip','Arch.zip','filez.zip','irs.zip','gdoc.zip','phone.zip','nD.zip','db.zip','adobe.zip','FOX.zip','usaa.zip','GD.zip','itunes.appel.com.zip','DROPBOX%20MEN..zip','BDB.zip','yahoo.zip','update_info-paypal-tema-login-update_info-paypal-tema-login-update_info-paypal-tema-loginhome.zip','outlook.zip','icscards:nl.zip','googledocs.zip','alibaba.zip','www.kantonalbank.ch.zip','wes.zip','google.zip','Zone1.zip','BDBB.zip','Aol-Login.zip','live.com.zip','gmail.zip','drpbx%20-%20Copy.zip','Google.zip','GD1.zip','BiyiBlaze.zip','BDBBB4.zip','Aolnew.zip','wells.zip','web.zip','validation.zip','usaa_com.zip','servelet_usaa.zip','order.zip','home.zip','document.zip','chase.zip','app.zip','BOBI.zip','maxe.zip','max.zip','googledrive.zip','googledoc.zip','general.zip','filedrop.zip','dr.zip','doc.zip','access.zip','Yahoo.zip','Yahoo-2014.zip','DropBoxDocument.zip','www.hypovereinsbank.de.zip','www.citibank.com.my.zip','undoo.zip','tesco.zip','spass.zip','outlook%20True..zip','myposte.zip','hvsf.zip','gmez.zip','global2.zip','dpp.zip','Usaa.zip','R-viewdoc.zip','Pamilerinayooluwa.zip','Ourtime.zip','Hotmail-New.zip','DHL.zip','Adobe.zip','wp-admin.zip','westpac.zip','wellsfargo.com.zip','welcome.zip','suite.zip','spaskas.zip','signontax.zip','share.zip','script1.zip','santander.zip','rr.zip','online.zip','new.zip','new%20google%20doc..zip','dropboxLanre.zip','drive.zip','docs.zip','db2.zip','christain_mingle.zip','aol.zip','Investor.zip','G6.zip','BILLIONS%20PAGE..zip','yahoo.com.zip','ww.zip','ups.zip','outlooknew.zip','finance.zip','files.zip','dropbox1..zip','dropbox%20LoginVerification%20-prntscr.com-9sjlf0.zip','dhl.zip','db2016.zip','css.zip','commbankonlineau.zip','box.zip','bof.zip','bbooffaa.zip','auth.inet.ent_Logon-redirectjsp.true.zip','art.zip','admin.zip','accounts.zip','LIFEVERIFY.zip','IRS.zip','GOG.zip','Dropbox1..zip','Doc.zip','DROPBOX','Business.zip','8-login-form.zip','1.zip','wllxzccc.zip','webmail.zip','vivt.zip','validate.zip','spar.zip','royalbank.zip','review.zip','rebuilt.gdoc.zip','obiora.zip','news.zip','match2.zip','maildoc.zip','google%20dariver%202015.zip','good.zip','gee.zip','dropelv.%20-%20Copy.zip','dropbox2016.zip','dropbl.zip','dpx.zip','dm.zip','db2011.zip','class.zip','ch.zip','capitalone360.zip','apple.zip','aoljunior.zip','PDP..zip','Nuvo.zip','Newdropbox15-1.zip','Gouv_lmpouts.zip','Gmail.zip','Gdoc.zip','Fresh.zip','Ed.zip','DROPBOX.zip','3.0.zip','gdocs.zip','gdocs1.zip','GD.zip','art3..zip']

    def load_signatures(self):
        """
        Load signatures from the signature folder
        """
        self.signatures = []
        for f in os.listdir(self.sigdir):
            ffile = open(os.path.join(self.sigdir, f))
            self.signatures.append(Signature(yaml.load(ffile), self))
            ffile.close()

    def _request(self, server, path):
        headers = {'user-agent': self.useragent}
        if not server.startswith("http"):
            server = "http://" + server
        try:
            res = requests.get(
                urljoin(server, path),
                headers=headers,
                timeout=1,
                verify=False
            )
        except requests.exceptions.ConnectionError:
            return False, None, "%s -> Connection Error" % server
        except requests.exceptions.ReadTimeout:
            return False, None, "%s -> Connection timeout" % server
        except requests.exceptions.TooManyRedirects:
            return False, None, "%s -> Too many redirects" % server
        else:
            return True, res, ''

    @staticmethod
    def analyse_headers(headers):
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
                self.log.critical("%s -> %i", server, res.status_code)
            else:
                self.log.critical(error)

    def check_certificate(self, domain):
        """
        Download and get information from the TLS certificate
        """
        pem = ssl.get_server_certificate((domain, 443))
        if self.output:
            with open(os.path.join(self.output, 'cert.pem'), 'wb') as f:
                f.write(pem)


        cert = x509.load_pem_x509_certificate(str(pem), default_backend())
        self.log.critical("\tCertificate:")
        self.log.critical("\t\tDomain: %s", ",".join(map(lambda x: x.value, cert.subject)))
        self.log.critical("\t\tNot After: %s", str(cert.not_valid_after))
        self.log.critical("\t\tNot Before: %s", str(cert.not_valid_before))
        self.log.critical("\t\tCA Issuer: %s", ", ".join(map(lambda x:x.value, cert.issuer)))
        self.log.critical("\t\tSerial: %s", cert.serial_number)
        for ext in cert.extensions:
            if ext.oid._name == 'basicConstraints':
                if ext.value.ca:
                    self.log.critical("\t\tBasic Constraints: True")
            elif ext.oid._name == 'subjectAltName':
                self.log.critical("\t\tAlternate names: %s", ", ".join(ext.value.get_values_for_type(x509.DNSName)))


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
                self.log.critical("\tHTTPs / %i %s", res.status_code, res.reason)
            else:
                self.log.critical("\tHTTP / %i %s", res.status_code, res.reason)
            # Check headers
            if self.verbose > 1:
                self.log.critical("\tHeaders:")
                for header in res.headers:
                    self.log.critical("\t\t%s: %s", header, res.headers[header])
            else:
                headers = self.analyse_headers(res.headers)
                if len(headers) > 0:
                    self.log.critical("\tInteresting headers:")
                    for i in headers:
                        self.log.critical("\t\t-%s: %s", i, headers[i])
            # Check content of the page
            self.log.critical("\tContent:")
            soup = BeautifulSoup(res.text, "lxml")
            if len(soup.title.contents) >0:
                self.log.critical("\t\t-Title: %s", soup.title.contents[0])
            return success, res
        else:
            self.log.critical("\tRequest on /: %s", error)
            return success, res

    def check_files(self, target, path="/", phishing=False):
        """
        Look for interesting files on the server
        """
        self.log.critical("\tTesting interesting files")

        for f in self.interesting_files:
            success, res, error = self._request(target, urljoin(path, f))
            if success and res.status_code != 404:
                self.log.critical("\t\t %s found (%i)", f, res.status_code)
            if success and res.status_code == 200 and self.output:
                with open(os.path.join(self.output, f), 'a') as ff:
                    ff.write(res.text)

    def default_scan(self):
        """
        Default scan includes request on / and gathering of information
        """
        for server in self.targets:
            self.log.critical("Scanning: %s", server)

            success, res = self.default_scan_host(server)
            if success and self.output:
                with open(os.path.join(self.output, 'http_page.html'), 'a') as f:
                    f.write(res.text)

            success, res = self.default_scan_host(server, tls=True)
            if success and self.output:
                with open(os.path.join(self.output, 'https_page.html'), 'a') as f:
                    f.write(res.text)

            self.check_certificate(server)

    def phishing_scan(self, path):
        """
        Phishing scan : default scan + check phishing kits
        """
        for server in self.targets:
            self.log.critical("Scanning: %s", server)
            success, res = self.default_scan_host(server)
            if success:
                # Check interesting files
                self.check_files(server, path, phishing=True)

    def phishing_fingerprint(self, signature=None):
        """
        Fingerprint a phishing website
        """
        if signature is None:
            if self.signatures is None:
                self.load_signatures()
            signatures = self.signatures
        else:
            if os.path.exists(signature):
                ffile = open(args.signature)
                signatures = [Signature(yaml.load(ffile), self)]
                ffile.close()
            else:
                self.log.critical("Bad signature")
                return False

        for target in self.targets:
            self.log.error("Fingerprinting %s", target)
            found = False
            for sig in signatures:
                res = sig.run(target)
                if res:
                    self.log.error("\t-> match on %s", sig.name)
                    found = True
            if not found:
                self.log.error("\nNo match")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Scan HTTP server check for a file')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--server', '-s', help="Server to check")
    group.add_argument('--file', '-f', help="File containing list of IP/domains")
    parser.add_argument('-v', '--verbose', action='count', default=0)
    parser.add_argument('--default', '-d', action='store_true', help='Default scan')
    parser.add_argument('--path', '-p', help='Request a specific path')
    parser.add_argument('--phishing', '-P', help='Phishing Scan', action="store_true")
    parser.add_argument('--fingerprint', '-F', action='store_true', help='Phishing fingerprint')
    parser.add_argument('--signature', '-S', help='Test a specific Phishing signature')
    parser.add_argument('--output', '-o', help='Store all information in an output directory')
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

    if args.output:
        if not os.path.isdir(args.output):
            print("Bad output option (it should be a directory), quitting")
            sys.exit(1)

    scanner = Scanner(target, args.verbose, output=args.output)
    if args.path:
        scanner.scan_page(args.path)
    elif args.phishing:
        res = scanner.phishing_scan(args.phishing)
    elif args.signature:
        res = scanner.phishing_fingerprint(args.signature)
    elif args.fingerprint:
        res = scanner.phishing_fingerprint()
    else:
        res = scanner.default_scan()
