import pprint
import argparse
import os, sys, re
from rico.util.debug import Debug
from rico.core.manager import Manager
from config import Config

# regex
reg_ipv4 = re.compile('^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$')
reg_ipv6 = re.compile('(([a-fA-F0-9]{1,4}|):){1,7}([a-fA-F0-9]{1,4}|:)')
reg_domain = re.compile('^((?:([a-z0-9]\.|[a-z0-9][a-z0-9\-]{0,61}[a-z0-9])\.)+)([a-z0-9]{2,63}|(?:[a-z0-9][a-z0-9\-]{0,61}[a-z0-9]))\.?$')
reg_email = re.compile('[a-z0-9!#$%&\'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&\'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?')
reg_mac = re.compile('^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$')

def main():
    #Debug.debug_log()
    # get api tokens
    tokens = Config.tokens
    #pprint.pprint(tokens)

    # read in arguments
    args = parse_arguments()

    # target dictionary to pass to Manager class
    targets = {
            'ip' : [],
            'mac' : [],
            'email' : [],
            'domain' : []
            }

    # sort the targets and append them to the list
    for target in args.targets:
        if reg_ipv4.match(target):
            targets['ip'].append(target)
        elif reg_domain.match(target):
            targets['domain'].append(target)

    manager = Manager(tokens, targets)
    manager.initialize()
    manager.run()

def parse_arguments():
    #Debug.debug_log()
    parser = argparse.ArgumentParser()
    parser.add_argument('targets', metavar='TARGETS', nargs='+',
                        help='targets to perform reconnaissance on')
    parser.add_argument('-d', '--debug', action='store_true',
                        help="activate debug mode")

    return parser.parse_args()



