import pprint
import curses
import re, os, sys
from rico.modules.

class Manager():
    def __init__(self, targets):
        self.ip = targets['ip']
        self.domain = targets['domain']
        self.mac = targets['mac']
        self.email = targets['email']
        self.windows = {
                'ip' : [],
                'mac' : [],
                'email' : [],
                'domain' : []
                }

    def initialize(self):
        for item in self.ip:
            print(item)

        for item in self.domain:
            print(item)

        for item in self.mac:
            print(item)

        for item in self.email:
            print(item)

    def run(self):
        while True:
            print('help')

