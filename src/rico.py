#!/usr/bin/env python3

import re
import os
import sys
import pprint
import curses
import helpers
import argparse
from curses import panel
from helpers import Abuseipdb, Greynoise, IPinfo, HybridAnalysis, Hostio, SecurityTrails, ThreatCrowd

token_hostio = '635a1e072c38a9'
token_ipinfo = '28e4e00f2aa4b5'
token_greynoise = 'tKwXOAeKyZIFoPA6IhADhSnPfaGLcvSrW2aYvu0zi70cx0b9arX72O313XuDBkBk'
token_abuseipdb = 'cc5f598a12bd018db3c323c1b59500d70d6bea0e7210f71e56c4dea616831a23e3ef8a35c9c644f5'
token_securitytrails = 'SWwMySUjJP2Wd5RqVsHRmgjDd46Ym6IZ'
token_hybridanalysis = 'kgup5cto6262d6539e4t8mrs59007eb6oci2q2vb33b38680supi0183eb504f17'

class Rico:
    def __init__(self, args=None):
        parser = argparse.ArgumentParser()
        parser.add_argument('targets', metavar='N', nargs='+', help='targets')
        self.args = parser.parse_args()

        self._sort_targets(self.args.targets)

    def _sort_targets(self, args):
        '^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$'

        self.targets_ip = []
        self.targets_mac = []
        self.targets_email = []
        self.targets_domain = []

        ipv4 = re.compile('^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$')
        ipv6 = re.compile('(([a-fA-F0-9]{1,4}|):){1,7}([a-fA-F0-9]{1,4}|:)')
        domain = re.compile('^((?:([a-z0-9]\.|[a-z0-9][a-z0-9\-]{0,61}[a-z0-9])\.)+)([a-z0-9]{2,63}|(?:[a-z0-9][a-z0-9\-]{0,61}[a-z0-9]))\.?$')
        email = re.compile('[a-z0-9!#$%&\'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&\'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?')
        mac = re.compile('^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$')

        for item in args:
            if ipv4.match(item): #or ipv6.match(item):
                self.targets_ip.append(item)
            elif domain.match(item):
                self.targets_domain.append(item)
            elif mac.match(item):
                self.targets_mac.append(item)
            elif email.match(item):
                self.targets_email.append(item)

    def dump_args(self):
        print('{}: {}'.format('IP ADDRESSES', self.targets_ip))
        print('{}: {}'.format('DOMAIN', self.targets_domain))
        print('{}: {}'.format('MAC ADDRESSES', self.targets_mac))
        print('{}: {}'.format('EMAIL', self.targets_email))

    def run(self):
        if self.targets_ip:
            abuseipdb = Abuseipdb(token_abuseipdb)
            ipinfo = IPinfo(token_ipinfo)
            greynoise = Greynoise(token_greynoise)

            for target in self.targets_ip:
                ipinfo.lookup_ip(target)
                greynoise.lookup_ip(target)
                abuseipdb.lookup_ip(target)

        if self.targets_domain:
            hostio = Hostio(token_hostio)
            securitytrails = SecurityTrails(token_securitytrails)

            for target in self.targets_domain:
                hostio.lookup_host(target)
                securitytrails.dns_history(target)

        #if self.targets_email:

        #if self.targets_mac:

def main():
    rico = Rico()
    rico.dump_args()
    rico.run()


if __name__ == "__main__":
    main()
    #curses.wrapper(GreynoiseRecon)
