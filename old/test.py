#!/usr/bin/env python3

import os, sys
#import helpers
from helpers import Greynoise, IPinfo, Abuseipdb, MalwareBazaar
import pprint

token_hostio = '635a1e072c38a9'
token_ipinfo = '28e4e00f2aa4b5'
token_greynoise = 'tKwXOAeKyZIFoPA6IhADhSnPfaGLcvSrW2aYvu0zi70cx0b9arX72O313XuDBkBk'
token_abuseipdb = 'cc5f598a12bd018db3c323c1b59500d70d6bea0e7210f71e56c4dea616831a23e3ef8a35c9c644f5'
token_malwarebazaar = 'SWwMySUjJP2Wd5RqVsHRmgjDd46Ym6IZ'

greynoise = Greynoise(token_greynoise)
ipinfo = IPinfo(token_ipinfo)
abuseipdb = Abuseipdb(token_abuseipdb)
malwarebazaar = MalwareBazaar()

#print("########################################################################")
res_greynoise = greynoise.lookup_ip_dict('61.163.145.244')

#print("########################################################################")
#res_ipinfo = ipinfo.lookup_ip('61.163.145.244')

#print("########################################################################")
#res_abuseipdb = abuseipdb.lookup_ip('61.163.145.244')

res_malwarebazaar = malwarebazaar.lookup_domain('7de2c1bf58bce09eecc70476747d88a26163c3d6bb1d85235c24a558d1f16754')

def print_dict(data, count=0):
    if type(data) is dict:
        for key, value in data.items():
            if type(value) is dict:
                print('{:^{spacing}}{:15} :'.format('', key, spacing=str(count*4)))
                print_dict(value, (count+1))

            elif type(value) is list :
                print_dict(value, (count+1))
            else:
                print('{:^{spacing}}{:15} : {}'.format('', key, value, spacing=str(count*4)))

    elif type(data) is list:
        for item in data:
            if type(item) is dict or type(item) is list:
                print_dict(item, (count+1))
            else:
                print('{:^{spacing}}{:15}'.format('', item, spacing=str(count*4)))

print_dict(res_malwarebazaar)
#print_dict(res_greynoise)



"""
#print("########################################################################")
#res_shodan = shodan.lookup_ip('85.214.100.6')

print("########################################################################")
print('dns history')
pprint.pprint(securitytrails.dns_history('microsoftonline.host'))
print("########################################################################")
print('dns whois')
pprint.pprint(securitytrails.history_whois('microsoftonline.host'))
print("########################################################################")
print('domain details')
pprint.pprint(securitytrails.domain_details('microsoftonline.host'))
print("########################################################################")
print('subdomains')
pprint.pprint(securitytrails.domain_subdomains('microsoftonline.host'))
print("########################################################################")
print('tags')
pprint.pprint(securitytrails.domain_tags('microsoftonline.host'))
"""
