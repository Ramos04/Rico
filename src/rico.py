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
            print('+----------------------------------------------------------+')
            print('| {:^56} |'.format('Gathering Info For: ' + target))
            print('+----------------------------------------------------------+')

            if self.reg_ipv4.match(target):
                self._recon_ip(target)

            elif self.reg_domain.match(target):
                self._recon_domain(target)


def main():
    #rico = Rico()
    rico.run()

class GreynoiseWindow(object):

    def __init__(self, stdscreen, num_splits, window_num, data):
        # get the height and width of screen passed in 
        full_height, full_width = stdscreen.getmaxyx()

        # window dimensions
        self.window_height = int (full_height)
        self.window_width = int (full_width/num_splits)

        # header sub window dimensions
        self.results_height = int (self.window_height/3)
        self.results_width = self.window_width
        self.results_start_line = 0
        self.results_start_col = 0

        # init main window
        # lines, columns, start line, start column
        self.window = curses.newwin(self.window_height,
                                    self.window_width,
                                    0,
                                    0)
        self.window.border()

        # init header sub window
        # lines, columns, start line, start column
        self.results = self.window.derwin(self.results_height,
                                          self.results_width,
                                          self.results_start_line,
                                          self.results_start_col)

        self.results.addstr(0, 0, '+----------------------------+')
        self.results.addstr(1, 0, '| {:^26} |'.format('GreyNoise'))
        self.results.addstr(2, 0, '+----------------------------+')

        count = 3
        if data:
            for k1, v1 in data.items():

                if type(v1) is list:
                    self.results.addstr(count, 0, str('{:15} :'.format(k1)))
                    count +=1
                    for item in v1:
                        if type(item) is dict:
                            for k2, v2 in item.items():
                                self.results.addstr(count, 0, str('    {:5} : {}'.format(k2, v2)))
                                count +=1
                        else:
                            self.results.addstr(count, 0, str('    {}'.format(item)))
                            count +=1
                elif type(v1) is dict:
                    self.results.addstr(count, 0, str('{:15} :'.format(k1)))
                    count +=1
                    for k2, v2 in v1.items():
                        self.results.addstr(count, 0, str('    {:11} :'.format(k2)))
                        count +=1
                        if type(v2) is list:
                            for item in v2:
                                self.results.addstr(count, 0, str('         {}'.format(item)))
                                count +=1
                        else:
                            self.results.addstr(count, 0, str('    {:5} : {}'.format(k2, v2)))
                            count +=1
                else:
                    self.results.addstr(count, 0, str('{:15} : {}'.format(k1, v1)))
                    count +=1

    def display(self):
        self.window.refresh()
        self.results.refresh()

# App object
class GUI(object):
    def __init__(self, stdscreen):
        self.screen = stdscreen
        greynoise = Greynoise(token_greynoise)

        #gn_results = greynoise.lookup_ip('61.163.145.244')
        gn_results = greynoise.lookup_ip_dict('61.163.145.244')


        # set the cursor
        curses.curs_set(0)

        gn_win = GreynoiseWindow(self.screen, 3, 0, gn_results)
        gn_win.display()

        curses.napms(3000)
        curses.endwin()

if __name__ == "__main__":
    #main()
    curses.wrapper(GUI)
