#!/usr/bin/env python3

import os, sys
import curses
from curses import panel

# Menu object
class Menu(object):
    def __init__(self, items, stdscreen):
        # set the menu items passed in 
        self.items = items

        # get the height and width of screen passed in 
        self.screen_height, self.screen_width = stdscreen.getmaxyx()

        self.window = stdscreen.subwin(0,0)
        self.window.keypad(1)

        # create a new panel 
        self.panel = panel.new_panel(self.window)
        self.panel.hide()
        panel.update_panels()

        self.position = 0

    def navigate(self, n):
        self.position += n
        if self.position < 0:
            self.position = 0
        elif self.position >= len(self.items):
            self.position = len(self.items) - 1

    def display(self):
        self.panel.top()
        self.panel.show()
        self.window.clear()

        while True:
            self.window.refresh()
            curses.doupdate()
            for index, item in enumerate(self.items):
                if index == self.position:
                    mode = curses.A_REVERSE
                else:
                    mode = curses.A_NORMAL

                msg = "%d. %s" % (index, item[0])
                self.window.addstr(1 + index, 1, msg, mode)

            key = self.window.getch()

            # handle the <enter> key
            if key in [curses.KEY_ENTER, ord("\n")]:
                if self.position == len(self.items) - 1:
                    break
                else:
                    self.items[self.position][1]()
            # handle <↓> key, move down 
            elif key == curses.KEY_DOWN:
                self.navigate(1)
            # handle <j> key, move down
            elif key in [curses.KEY_ENTER, ord("j")]:
                self.navigate(1)
            # handle <↑> key, move up
            elif key == curses.KEY_UP:
                self.navigate(-1)
            # handle <k> key, move up
            elif key in [curses.KEY_ENTER, ord("k")]:
                self.navigate(-1)

        self.window.clear()
        self.panel.hide()
        panel.update_panels()
        curses.doupdate()

# App object
class MyApp(object):
    def __init__(self, stdscreen):
        self.screen = stdscreen

        # set the cursor
        curses.curs_set(0)

        main_menu_items = [
            ("beep", curses.beep),
            ("aaaaaaaaaaaaaaaaaaaaa", curses.beep),
            ("flash", curses.flash),
            ("exit", curses.beep)
        ]

        main_menu = Menu(main_menu_items, self.screen)
        main_menu.display()

if __name__ == "__main__":
    curses.wrapper(MyApp)

