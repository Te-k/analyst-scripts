#! /usr/bin/env python3
import argparse
from IPy import IP
import pyshark


class Pcap(object):
    def __init__(self, ffile):
        self.file = ffile
        self._indicators = None
        self._dns_resolutions = {}

    def dns_resolution(self, ip):
        if ip in self._dns_resolutions:
            return self._dns_resolutions[ip]
        else:
            return None

    @property
    def indicators(self):
        if self._indicators is None:
            self.extract_indicators()
        return self._indicators

    def _resolution_add(self, ip, domain):
        if ip not in self._dns_resolutions:
            self._dns_resolutions[ip] = [domain]
        else:
            if domain not in self._dns_resolutions[ip]:
                self._dns_resolutions[ip].append(domain)

    def _indicators_add(self, type, value):
        new_indicator = {'type': type, 'value': value}
        if new_indicator not in self._indicators:
            self._indicators.append(new_indicator)

    def _extract_ip(self, pkt):
        """
        Extract indicators at TCP level
        Add them to the global indicators
        """
        if IP(pkt['IP'].src).iptype() != 'PRIVATE':
            self._indicators_add('ip', pkt['IP'].src)
        if IP(pkt['IP'].dst).iptype() != 'PRIVATE':
            self._indicators_add('ip', pkt['IP'].dst)

    def _extract_dns(self, p):
        """
        Extract indicators at DNS level
        Adds them directly to the ioc list
        """
        if p['DNS'].flags_response == '0':
            # QUERY
            self._indicators_add('domain', p['DNS'].qry_name)
        else:
            self._indicators_add('domain', p['DNS'].qry_name)
            # RESPONSE
            if hasattr(p['DNS'], 'cname'):
                # TODO ?
                pass
            if hasattr(p['DNS'], 'a'):
                for a in p['DNS'].a.all_fields:
                    ip = a.get_default_value()
                    self._indicators_add('ip', ip)
                    self._resolution_add(ip, p['DNS'].qry_name)
            if hasattr(p['DNS'], 'aaaa'):
                for aaaa in p['DNS'].aaaa.all_fields:
                    ip = aaaa.get_default_value()
                    self._indicators_add('ip', ip)
                    self._resolution_add(ip, p['DNS'].qry_name)

    def _extract_http(self, p):
        """
        Extract IOCs are HTTP level
        Add the indicators to the global IOC list
        """
        if hasattr(p['HTTP'], 'host'):
            self._indicators_add('domain', p['HTTP'].host)
        if p['HTTP'].get_field('User-Agent'):
                self._indicators_add(
                    'user-agent',
                    p['HTTP'].get_field('User-Agent')
                )
        if hasattr(p['HTTP'], 'request_uri'):
            # Check if it is a query
            if hasattr(p['HTTP'], 'host'):
                self._indicators_add(
                    'url',
                    'http://%s%s' % (p['HTTP'].host, p['HTTP'].request_uri)
                )
            else:
                self._indicators_add(
                    'url',
                    'http://%s%s' % (p['IP'].dst, p['HTTP'].request_uri)
                )

    def _extract_ssl(self, p):
        """
        Extract IOCs from the SSL layer
        """
        if 'SSL' in p:
            for layer in p.layers:
                if layer.layer_name == 'ssl':
                    if hasattr(layer, 'x509ce_dnsname'):
                        self._indicators_add('domain', layer.x509ce_dnsname)

    def extract_indicators(self):
        """
        Extract indicators from the pcap file
        """
        self._indicators = []
        try:
            pkts = pyshark.FileCapture(self.file)
            for p in pkts:
                if 'IP' in p:
                    self._extract_ip(p)
                if 'DNS' in p:
                    self._extract_dns(p)
                if 'HTTP' in p:
                    self._extract_http(p)
                if 'SSL' in p:
                    self._extract_ssl(p)
        except pyshark.tshark.tshark.TSharkNotFoundException:
            print('tshark is not installed, please install it')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Extract IOCs from a PCAP')
    parser.add_argument('FILE', help='File')
    args = parser.parse_args()

    pcap = Pcap(args.FILE)
    for i in pcap.indicators:
        if i['type'] == 'ip':
            if pcap.dns_resolution(i['value']):
                print('{} - {} - DNS resolution: {}'.format(i['type'], i['value'], ','.join(pcap.dns_resolution(i['value']))))
            else:
                print('%s - %s - No DNS Resolution' % (i['type'], i['value']))
        else:
            print('%s - %s' % (i['type'], i['value']))

