import os
import requests
import json
import pprint

#token_hostio = '635a1e072c38a9'
#token_ipinfo = '28e4e00f2aa4b5'
#token_greynoise = 'tKwXOAeKyZIFoPA6IhADhSnPfaGLcvSrW2aYvu0zi70cx0b9arX72O313XuDBkBk'

def jsonToString(data):
    ret_str =''
    for key, value in data.items():
        print(str(type(key)))
        if type(value) is dict:
            parseJson(value)
        else:
            ret_str = ret_str + "{0} : {1}".format(key,value) + "\n"
            #print("{0} : {1}".format(key,value))

    return ret_str

class Greynoise:
    def __init__ (self, token):
        self.token = token

    def lookup_ip(self, ip_addr, ret_json=False):
        url = 'https://api.greynoise.io/v2/noise/context/'
        headers = {'accept': 'application/json', 'key': self.token}

        response = requests.request("GET", url, headers=headers)
        print("DATA")
        pprint.pprint(response)
        data = response.json()
        print("\n")

        print("DATA")
        pprint.pprint(data)
        print("\n")

        if ret_json:
            return data

        return jsonToString(data)

class IPinfo:
    def __init__ (self, token):
        self.token = token

    def lookup_ip(self, ip_addr, json=False):
        url = 'https://ipinfo.io/' + ip_addr + '?token=' + self.token
        headers = {'accept': 'application/json'}

        response = requests.request("GET", url, headers=headers)
        data = response.json()

        if ret_json:
            return data

        return jsonToString(data)

class Hostio:
    def __init__ (self, token):
        self.token = token

    def lookup_ip(self, host_name, json=False):
        response = requests.get('https://host.io/api/full/' + host_name + '?token=' + self.token)
        data = response.json()

        if ret_json:
            return data

        return jsonToString(data)

class ThreatCrowd:
    def lookup_ip(self, ip_addr, json=False):
        url = 'http://www.threatcrowd.org/searchApi/v2/ip/report/'
        req_params = {'ip': ip_addr}

        response = requests.get(url, params=req_params)
        data = response.json()

        if ret_json:
            return data

        return jsonToString(data)
