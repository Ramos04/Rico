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
    reg_ipv4 = re.compile('^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$')
    reg_ipv6 = re.compile('(([a-fA-F0-9]{1,4}|):){1,7}([a-fA-F0-9]{1,4}|:)')
    reg_domain = re.compile('^((?:([a-z0-9]\.|[a-z0-9][a-z0-9\-]{0,61}[a-z0-9])\.)+)([a-z0-9]{2,63}|(?:[a-z0-9][a-z0-9\-]{0,61}[a-z0-9]))\.?$')
    reg_email = re.compile('[a-z0-9!#$%&\'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&\'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?')
    reg_mac = re.compile('^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$')

    def __init__(self, args=None):
        parser = argparse.ArgumentParser()
        parser.add_argument('targets', metavar='N', nargs='+', help='targets')
        self.args = parser.parse_args()

        # set up recon helpers
        self.targets = self.args.targets
        self.abuseipdb = Abuseipdb(token_abuseipdb)
        self.ipinfo = IPinfo(token_ipinfo)
        self.greynoise = Greynoise(token_greynoise)
        self.hostio = Hostio(token_hostio)
        self.securitytrails = SecurityTrails(token_securitytrails)

    def _recon_ip(self, target):
        self.ipinfo.lookup_ip(target)
        self.greynoise.lookup_ip(target)
        self.abuseipdb.lookup_ip(target)

    def _recon_domain(self, target):
        self.hostio.lookup_host(target)
        self.securitytrails.dns_history(target)

    def run(self):
        for target in self.targets:
            if self.reg_ipv4.match(target):
                self._recon_ip(target)

            elif self.reg_domain.match(target):
                self._recon_domain(target)

def main():
    rico = Rico()
    rico.run()


if __name__ == "__main__":
    main()
    #curses.wrapper(GreynoiseRecon)
