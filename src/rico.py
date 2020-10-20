#!/usr/bin/env python3

import os, sys
import pprint
import curses
import helpers
from curses import panel
#from helpers import Greynoise, IPinfo, Hostio, ThreatCrowd

token_hostio = '635a1e072c38a9'
token_ipinfo = '28e4e00f2aa4b5'
token_greynoise = 'tKwXOAeKyZIFoPA6IhADhSnPfaGLcvSrW2aYvu0zi70cx0b9arX72O313XuDBkBk'

class GreynoiseWindow(object):
    def __init__(self, stdscreen):
        # get the height and width of screen passed in 
        self.window_height, self.window_width = stdscreen.getmaxyx()

        # init the entire window
        self.window = curses.newwin(self.window_height, self.window_width, 0, 0)

        # left header 
        self.head_l_height = int (self.window_height/8)
        self.head_l_width = int (self.window_width/2)
        self.head_l_line = 0
        self.head_l_col = 0

        # right header
        self.head_r_height = int (self.window_height/8)
        self.head_r_width = int (self.window_width/2)
        self.head_r_line = 0
        self.head_r_col = int (self.window_width/2)

        # body left
        self.body_l_height = int (self.window_height/7/8)
        self.body_l_width = int (self.window_width/2/3)
        self.body_l_line = int (self.window_height/7/8)
        self.body_l_col = 0

        # body right
        self.body_r_height = int (self.window_height/7/8)
        self.body_r_width = int (self.window_width/1/3)
        self.body_r_line = int (self.window_height/7/8)
        self.body_r_col = int (self.window_width/2/3)


        self.head_l = self.window.derwin(self.head_l_height,
                                         self.head_l_width,
                                         self.head_l_line,
                                         self.head_l_col)
        self.head_l.border()

        self.head_r = self.window.derwin(self.head_r_height,
                                         self.head_r_width,
                                         self.head_r_line,
                                         self.head_r_col)
        self.head_r.border()

        self.body_l = self.window.derwin(self.body_l_height,
                                         self.body_l_width,
                                         self.body_l_line,
                                         self.body_l_col)
        self.body_l.border()

        self.body_r = self.window.derwin(self.body_r_height,
                                         self.body_r_width,
                                         self.body_r_line,
                                         self.body_r_col)
        self.body_r.border()

    def display(self):
        self.window.refresh()

        self.head_l.refresh()
        self.head_r.refresh()

        """
        self.body_l.refresh()
        self.body_r.refresh()
        """

# App object
class GreynoiseRecon(object):
    def __init__(self, stdscreen):
        self.screen = stdscreen
        #greynoise = Greynoise(token_greynoise)

        #gn_results = greynoise.lookup_ip('61.163.145.244', ret_list=True)

        # set the cursor
        curses.curs_set(0)

        gn_win = GreynoiseWindow(self.screen)
        gn_win.display()

        curses.napms(3000)
        curses.endwin()

if __name__ == "__main__":
    curses.wrapper(GreynoiseRecon)
