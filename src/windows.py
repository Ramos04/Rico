#!/usr/bin/env python3

import curses
import re, os, sys

class SubWindow():
    def __init__(self, window, num_splits, num_pos):
        self.window = window
        height, width = window.getmaxyx()

        self.height = height
        self.width = int(width/num_splits)

        self.border_height = 4
        self.border_width = self.width
        self.border_col = 0
        self.border_lin = 0

        self.body_height = int(self.height-4)
        self.body_width = self.width
        self.body_col = 0
        self.body_lin = 4

        self.header = self.window.derwin(self.border_height,
                                         self.width,
                                         self.border_lin,
                                         self.border_col)
        self.header.border()

        self.body = self.window.derwin(self.body_height,
                                       self.body_width,
                                       self.body_lin,
                                       self.body_col)
        self.body.border()

    def display(self):
        self.header.refresh()
        self.body.refresh()

class Window():
    def __init__(self, stdscr):
        self.screen = stdscr
        self.height, self.width = self.screen.getmaxyx()

        self.new_win = curses.newwin(self.height, self.width, 0, 0)
        self.new_win.border()

        self.sub_win = SubWindow(self.new_win, 3, 0)

        self.new_win.refresh()
        self.sub_win.display()
        curses.napms(3000)
        curses.endwin()

def main():
    curses.wrapper(Window)

if __name__ == "__main__":
    main()
