#!/usr/bin/env python3

import os
import requests
import json
import pprint
import Greynoise

token_hostio = '635a1e072c38a9'
token_ipinfo = '28e4e00f2aa4b5'
token_greynoise = 'tKwXOAeKyZIFoPA6IhADhSnPfaGLcvSrW2aYvu0zi70cx0b9arX72O313XuDBkBk'

def request_hostio(host_name):
    response = requests.get('https://host.io/api/full/' + host_name + '?token=' + token_hostio)
    data = response.json()

    return data


def request_ipinfo(ip_addr):
    url = "https://ipinfo.io/" + ip_addr + '?token=' + token_hostio
    headers = {"accept": "application/json"}

    response = requests.request("GET", url, headers=headers)
    data = response.json()

    return data

def request_greynoise(ip_addr):
    url = "https://api.greynoise.io/v2/noise/context/" + ip_addr
    headers = {"accept": "application/json", "key": token_greynoise}

    response = requests.request("GET", url, headers=headers)
    data = response.json()

    return data

def request_threatcrowd(ip_addr):
    url = "http://www.threatcrowd.org/searchApi/v2/ip/report/"
    req_params = {"ip": ip_addr}

    response = requests.get(url, params=req_params)

    data = response.json()

    return data

def parseJson(data):
    for key, value in data.items():
        print(str(type(key)))
        if type(value) is dict:
            parseJson(value)
        else:
            print("{0} : {1}".format(key,value))

if __name__ == '__main__':
    """
    print('HOST.IO')
    parseJson(request_hostio('hurricanelabs.com'))
    print('\n')

    print('IPINFO.IO')
    parseJson(request_ipinfo('61.163.145.244'))
    print('\n')

    print('GREYNOISE')
    parseJson(request_greynoise("61.163.145.244"))
    print('\n')
    """

    greynoise = Greynoise.Greynoise(token_greynoise, "ip", "188.40.75.132")

    str(type(greynoise.dump))

    #parseJson(greynoise.dump)
    #print('THREATCROWD')
    #parseJson(request_threatcrowd("188.40.75.132"))
    #parseJson(request_threatcrowd("61.163.145.244"))
    #print('\n')
