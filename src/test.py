#!/usr/bin/env python3

import os, sys
import helpers
#from helpers import Greynoise, IPinfo, Hostio, ThreatCrowd
import pprint

token_hostio = '635a1e072c38a9'
token_ipinfo = '28e4e00f2aa4b5'
token_greynoise = 'tKwXOAeKyZIFoPA6IhADhSnPfaGLcvSrW2aYvu0zi70cx0b9arX72O313XuDBkBk'


greynoise = Greynoise(token_greynoise)
print(greynoise.lookup_ip('61.163.145.244'))

#ii_json = apis.request_ipinfo('61.163.145.244')
#ii_str = apis.parseJson(ii_json)

#pprint.pprint(ii_json)
#print(ii_str)

#gn_json = apis.request_greynoise('61.163.145.244')
#gn_str = apis.parseJson(gn_json)

#pprint.pprint(gn_json)
#print(gn_str)


