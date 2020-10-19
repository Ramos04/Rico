#!/usr/bin/env python3

import os, sys
import curses
import helpers
from curses import panel
from helpers import Greynoise, IPinfo, Hostio, ThreatCrowd

token_hostio = '635a1e072c38a9'
token_ipinfo = '28e4e00f2aa4b5'
token_greynoise = 'tKwXOAeKyZIFoPA6IhADhSnPfaGLcvSrW2aYvu0zi70cx0b9arX72O313XuDBkBk'

class WinGreynoise(object):
    def __init__(self, stdscreen, split_num, text):
        # get the height and width of screen passed in 
        #self.screen_height, self.screen_width = stdscreen.getmaxyx()
        temp_height, temp_width = stdscreen.getmaxyx()

        self.screen_height = int (temp_height)
        self.screen_width = int (temp_width/split_num)

        # lines, columns, start line, start column
        #self.window = curses.newwin(int(self.screen_height), int(self.screen_width/3), 0, 0)
        self.window = curses.newwin(self.screen_height+3, self.screen_width-3, 3, 3)
        self.window.border()
        self.window.addstr(text)

    def display(self):
        self.window.refresh()

class WinThreatCrowd(object):
    def __init__(self, stdscreen, split_num, text):
        # get the height and width of screen passed in 
        temp_height, temp_width = stdscreen.getmaxyx()

        self.screen_height = int (temp_height)
        self.screen_width = int (temp_width/split_num)

        # lines, columns, start line, start column
        #self.window = curses.newwin(int(self.screen_height), 60, 0, 60)
        self.window = curses.newwin(self.screen_height-3, self.screen_width-3, 3, self.screen_width+3)
        self.window.border()
        self.window.addstr(text)

    def display(self):
        self.window.refresh()

# App object
class IPRecon(object):
    def __init__(self, stdscreen):
        self.screen = stdscreen
        greynoise = Greynoise(token_greynoise)
        gn_results = greynoise.lookup_ip('61.163.145.244')

        threatcrowd = ThreatCrowd()
        tc_results = threatcrowd.lookup_ip('188.40.75.132')

        # set the cursor
        curses.curs_set(0)

        gn_win = WinGreynoise(self.screen, 3,gn_results)
        gn_win.display()

        tc_win = WinThreatCrowd(self.screen, 3, gn_results)
        tc_win.display()

        curses.napms(10000)
        curses.endwin()

if __name__ == "__main__":
    #hostio = request_hostio('hurricanelabs.com')
    #ipinfo = request_ipinfo('61.163.145.244')
    #greynoise = request_greynoise('188.40.75.132')
    curses.wrapper(IPRecon)

#!/usr/bin/env python3

import os, sys
#import helpers
from helpers import Greynoise, IPinfo, Hostio, ThreatCrowd
import pprint



