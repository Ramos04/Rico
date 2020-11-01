import pprint
import curses
import ruamel.yaml
import re, os, sys, yaml, json
from rico.modules.ip import IP
from rico.util.debug import Debug
from rico.util.parse import Parse
from rico.util.colors import Colors
from rico.gui.gui import Window

class Manager():
    def __init__(self, tokens, args, targets):
        # set the passed in targets to vars for easier use
        self._targets_ip = targets['ip']
        self._args = args

        # set the passed in tokens to vars for easier use
        self._tokens = tokens

        # dict holds all the results with the target as the key
        self._dict_ip = {}

    def initialize(self):
        for target in self._targets_ip:
            self._dict_ip[target] = IP.recon(self._tokens, target)

    def run(self):
        if self._args.output == 'T':
            for k1, v1 in self._dict_ip.items():
                for k2, v2 in v1.items():
                    print(Colors.WARNING + '┌────────────────────────────────────────┐' + Colors.ENDC)
                    print(Colors.WARNING + '│{:^53}'.format(Colors.FAIL + Colors.UNDERLINE + k2 + Colors.ENDC) + Colors.WARNING + '│' + Colors.ENDC)
                    print(Colors.WARNING + '│' + Colors.ENDC + '{:^40}'.format(k1) + Colors.WARNING + '│' + Colors.ENDC)
                    #print('│{:^40}│'.format(k1))
                    print(Colors.WARNING + '└────────────────────────────────────────┘' + Colors.ENDC)

                    print(yaml.dump(v2))
        else:
            for key, value in self._dict_ip.items():
                ip_window = Window(value)
                ip_window.display()
