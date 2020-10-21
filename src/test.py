#!/usr/bin/env python3

import os, sys
#import helpers
from helpers import Greynoise, IPinfo, Hostio, ThreatCrowd
import pprint

token_hostio = '635a1e072c38a9'
token_ipinfo = '28e4e00f2aa4b5'
token_greynoise = 'tKwXOAeKyZIFoPA6IhADhSnPfaGLcvSrW2aYvu0zi70cx0b9arX72O313XuDBkBk'


greynoise = Greynoise(token_greynoise)
print(greynoise.lookup_ip('61.163.145.244'))

threatcrowd = ThreatCrowd()
print(threatcrowd.lookup_ip('188.40.75.132'))

ipinfo = IPinfo(token_greynoise)
print(ipinfo.lookup_ip('61.163.145.244'))
