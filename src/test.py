#!/usr/bin/env python3

import os, sys
#import helpers
from helpers import Greynoise, IPinfo, Hostio, ThreatCrowd, Shodan
import pprint

token_hostio = '635a1e072c38a9'
token_ipinfo = '28e4e00f2aa4b5'
token_greynoise = 'tKwXOAeKyZIFoPA6IhADhSnPfaGLcvSrW2aYvu0zi70cx0b9arX72O313XuDBkBk'
token_shodan = 'sq7r7leHpAtAk5we7Yf6YVALi7rmCWvY'

greynoise = Greynoise(token_greynoise)
ipinfo = IPinfo(token_ipinfo)
shodan = Shodan(token_shodan)

print("########################################################################")
res_greynoise = greynoise.lookup_ip('61.163.145.244')

print("########################################################################")
res_ipinfo = ipinfo.lookup_ip('61.163.145.244')

#print("########################################################################")
res_shodan = shodan.lookup_ip('85.214.100.6')
