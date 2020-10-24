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

import curses
import re, os, sys

class SubWindow():
    def __init__(self, window, num_splits, num_pos, module, data):
        self.window = window
        height, width = window.getmaxyx()

        self.height = height
        self.width = int(width/num_splits)

        self.border_height = 3
        self.border_width = self.width
        self.border_col = int(self.width*num_pos)
        self.border_lin = 0

        self.body_height = int(self.height-3)
        self.body_width = self.width
        self.body_col = int(self.width*num_pos)
        self.body_lin = 3

        # set the header of the sub window
        self.header = self.window.derwin(self.border_height,
                                         self.width,
                                         self.border_lin,
                                         self.border_col)
        self.header.border()

        # set the body of the sub
        self.body = self.window.derwin(self.body_height,
                                       self.body_width,
                                       self.body_lin,
                                       self.body_col)
        self.body.border()

        #self.body.addstr(0, 0, '+----------------------------+')
        #self.body.addstr(1, 0, '| {:^26} |'.format('GreyNoise'))
        #self.body.addstr(2, 0, '+----------------------------+')

        self.header.addstr(1, int( (self.width/2) - len(module)/2 ), module)
        count = 1
        if data:
            for k1, v1 in data.items():

                if type(v1) is list:
                    self.body.addstr(count, 1, str('{:15} :'.format(k1)))
                    count +=1
                    for item in v1:
                        if type(item) is dict:
                            for k2, v2 in item.items():
                                self.body.addstr(count, 1, str('    {:5} : {}'.format(k2, v2)))
                                count +=1
                        else:
                            self.body.addstr(count, 1, str('    {}'.format(item)))
                            count +=1
                elif type(v1) is dict:
                    self.body.addstr(count, 1, str('{:15} :'.format(k1)))
                    count +=1
                    for k2, v2 in v1.items():
                        self.body.addstr(count, 1, str('    {:11} :'.format(k2)))
                        count +=1
                        if type(v2) is list:
                            for item in v2:
                                self.body.addstr(count, 1, str('         {}'.format(item)))
                                count +=1
                        else:
                            self.body.addstr(count, 1, str('    {:5} : {}'.format(k2, v2)))
                            count +=1
                else:
                    self.body.addstr(count, 1, str('{:15} : {}'.format(k1, v1)))
                    count +=1

    def display(self):
        self.header.refresh()
        self.body.refresh()

class Window():
    def __init__(self, stdscr):
        self.screen = stdscr
        self.height, self.width = self.screen.getmaxyx()

        greynoise = Greynoise(token_greynoise)
        ipinfo = IPinfo(token_ipinfo)

        res_greynoise = greynoise.lookup_ip_dict('61.163.145.244')
        res_ipinfo = ipinfo.lookup_ip_dict('61.163.145.244')

        self.new_win = curses.newwin(self.height, self.width, 0, 0)
        self.new_win.border()

        self.sub_greynoise = SubWindow(self.new_win, 3, 0, 'Greynoise', res_greynoise)
        self.sub_ipinfo = SubWindow(self.new_win, 3, 1, 'IP Info', res_ipinfo)

        self.new_win.refresh()
        self.sub_greynoise.display()
        self.sub_ipinfo.display()

        curses.napms(5000)
        curses.endwin()

def main():
    curses.wrapper(Window)

if __name__ == "__main__":
    main()
