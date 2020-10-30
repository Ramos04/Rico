import pprint
import curses
import re, os, sys
from rico.util.debug import Debug

class Window():
    #def __init__(self, stdscr):
    def __init__(self, data):
        self.screen = curses.initscr()
        self.data = data
        self.height, self.width = self.screen.getyx()
        #self.height, self.width = curses.LINES, curses.COLS

    def display(self):
        #Debug.debug_log()
        #pprint.pprint(self.data)

        self.new_win = curses.newwin(self.height, self.width, 0, 0)
        self.new_win.border()

        """
        self.sub_greynoise = SubWindow(self.new_win, 3, 0, 'Greynoise', self.data['greynoise'])
        self.sub_ipinfo = SubWindow(self.new_win, 3, 1, 'IP Info', self.data['ipinfo'])
        self.sub_abuseipdb = SubWindow(self.new_win, 3, 1, 'IP Info', self.data['abuseipdb'])
        """

        self.sub_greynoise = SubWindow(self.new_win, 3, 0, 'Greynoise', 'Greynoise test')
        self.sub_ipinfo = SubWindow(self.new_win, 3, 1, 'IP Info', 'IP Info test')
        self.sub_abuseipdb = SubWindow(self.new_win, 3, 2, 'Abuse IPDB', 'Abuse IP DB test')

        self.new_win.refresh()
        self.sub_greynoise.display()
        self.sub_ipinfo.display()
        self.sub_abuseipdb.display()

        curses.napms(5000)
        curses.endwin()

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

        self.header.addstr(1, int( (self.width/2) - len(module)/2 ), module)
        count = 1

        self.body.addstr(count, 1, data)
        """
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
        """

    def display(self):
        self.header.refresh()
        self.body.refresh()


