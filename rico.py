#!/usr/bin/env python3

import os, sys
import curses
import apis
from curses import panel

class WinGreynoise(object):
    def __init__(self, stdscreen, text):
        # get the height and width of screen passed in 
        self.screen_height, self.screen_width = stdscreen.getmaxyx()

        # lines, columns, start line, start column
        self.window = curses.newwin(int(self.screen_height), int(self.screen_width/3), 0, 0)
        self.window.addstr(text)

    def display(self):
        self.window.refresh()

# App object
class IPRecon(object):
    def __init__(self, stdscreen):
        self.screen = stdscreen

        #ipinfo = request_ipinfo('61.163.145.244')
        gn_json = apis.request_greynoise('61.163.145.244')
        gn_str = apis.parseJson(gn_json)

        # set the cursor
        curses.curs_set(0)

        greynoise = WinGreynoise(self.screen, gn_str)
        greynoise.display()

        curses.napms(10000)
        curses.endwin()

if __name__ == "__main__":
    #hostio = request_hostio('hurricanelabs.com')
    #ipinfo = request_ipinfo('61.163.145.244')
    #greynoise = request_greynoise('188.40.75.132')
    curses.wrapper(IPRecon)

