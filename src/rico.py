#!/usr/bin/env python3

import os, sys
import curses
import helpers
from curses import panel
from helpers import Greynoise, IPinfo, Hostio, ThreatCrowd

token_hostio = '635a1e072c38a9'
token_ipinfo = '28e4e00f2aa4b5'
token_greynoise = 'tKwXOAeKyZIFoPA6IhADhSnPfaGLcvSrW2aYvu0zi70cx0b9arX72O313XuDBkBk'

class WinTitle(object):
    def __init__(self, stdscreen, num_splits, text):
        # get the height and width of screen passed in 
        full_height, full_width = stdscreen.getmaxyx()

        self.screen_height = int (full_height/8)
        self.screen_width = int (full_width/num_splits)

        # lines, columns, start line, start column
        self.window = curses.newwin(self.screen_height, self.screen_width, 0, 0)
        #self.window.border()
        self.window.addstr(2, 2, text)

    def display(self):
        self.window.refresh()

class ResultsWindow(object):
    def __init__(self, stdscreen, num_splits, window_num, text):
        # get the height and width of screen passed in 

        full_height, full_width = stdscreen.getmaxyx()

        # window dimensions
        self.window_height = int (full_height)
        self.window_width = int (full_width/num_splits)

        # header sub window dimensions
        self.header_height = int (self.window_height/8)
        self.header_width = self.window_width
        self.header_start_line = 0
        self.header_start_col = 0

        # body sub window dimensions
        self.body_height = int(self.window_height/8)
        self.body_width = self.window_width
        self.body_start_line = int (self.window_height/8)
        self.body_start_col = 0

        # init main window
        # lines, columns, start line, start column
        self.window = curses.newwin(self.window_height,
                                    self.window_width,
                                    0,
                                    int(self.header_width * window_num))

        # init header sub window
        # lines, columns, start line, start column
        self.header = self.window.derwin(self.header_height,
                                         self.header_width,
                                         self.header_start_line,
                                         self.header_start_col)
        self.header.border()

        self.body = self.window.derwin(self.body_height,
                                       self.body_width,
                                       self.body_start_line,
                                       self.body_start_col)
        self.body.border()


    def display(self):
        self.window.refresh()
        self.header.refresh()
        self.body.refresh()

# App object
class IPRecon(object):
    def __init__(self, stdscreen):
        self.screen = stdscreen
        greynoise = Greynoise(token_greynoise)
        gn_results = greynoise.lookup_ip('61.163.145.244')

        # set the cursor
        curses.curs_set(0)

        gn_win = ResultsWindow(self.screen, 3, 1, "text")
        gn_win.display()

        curses.napms(3000)
        curses.endwin()

if __name__ == "__main__":

    curses.wrapper(IPRecon)

