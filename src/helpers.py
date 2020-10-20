import os
import requests
import json
import pprint

#token_hostio = '635a1e072c38a9'
#token_ipinfo = '28e4e00f2aa4b5'
#token_greynoise = 'tKwXOAeKyZIFoPA6IhADhSnPfaGLcvSrW2aYvu0zi70cx0b9arX72O313XuDBkBk'

def jsonToString(data, count=0):
    data_type = type(data)
    indent_len = 1

    if data_type is dict:
        for key, value in data.items():
            if type(value) is dict or type(value) is list:
                #print('{}{:13} :'.format(str('\t'*count), key))
                print('{}{} :'.format(str('\t'*count), key))
                jsonToString(value, count+1)

            else:
                #print('{}{:13} : {}'.format(str('\t'*count), key, value))
                print('{}{} : {}'.format(str('\t'*count), key, value))
    elif data_type is list:
        for item in data:
            if type(item) is dict or type(item) is list:
                jsonToString(item, count+1)

            else:
                #print('{}{:13}'.format(str('\t'*count), item))
                print('{}{}'.format(str('\t'*count), item))
    return None

def jsonFlatten(data, ret_str=''):
    data_type = type(data)

    if data_type is dict:
        for key, value in data.items():
            if type(value) is dict or type(value) is list:
                ret_str += '{:15} :\n'.format(key)
                ret_str = jsonFlatten(value, ret_str)

            else:
                #print('{:15} : {}'.format(key, value))
                ret_str += '{:15} : {}\n'.format(key, value)
    elif data_type is list:
        for item in data:
            if type(item) is dict or type(item) is list:
                ret_str = jsonFlatten(item, ret_str)

            else:
                ret_str += '{:13}\n'.format(item)

    return ret_str

def asciiArt(text):
    url = "https://artii.herokuapp.com/make?text=" + text + "&font=big"
    response = requests.request("GET", url)
    print(response)

    #data = response.json()
    #pprint.pprint(data)

class Greynoise:
    def __init__ (self, token):
        self.token = token

    def lookup_ip(self, ip_addr, ret_json=False):
        url = "https://api.greynoise.io/v2/noise/context/" + ip_addr
        headers = {
            "accept": "application/json",
            "key": "tKwXOAeKyZIFoPA6IhADhSnPfaGLcvSrW2aYvu0zi70cx0b9arX72O313XuDBkBk"
        }

        response = requests.request("GET", url, headers=headers)

        data = response.json()

        if response.status_code != 200:
            print(response.status_code + "\n")
            pprint.pprint(data)
            return None

        #pprint.pprint(data)

        if ret_json:
            return data

        #jsonToString(data)
        return jsonFlatten(data)

class IPinfo:
    def __init__ (self, token):
        self.token = token

    def lookup_ip(self, ip_addr, ret_json=False):
        url = 'https://ipinfo.io/' + ip_addr + '?token=' + self.token
        #headers = {'accept': 'application/json'}

        response = requests.request("GET", url)
        data = response.json()

        if response.status_code != 200:
            print(response.status_code + "\n")
            pprint.pprint(data)
            return None


        if ret_json:
            return data

        #return jsonToString(data)
        return jsonFlatten(data)

class Hostio:
    def __init__ (self, token):
        self.token = token

    def lookup_ip(self, host_name, ret_json=False):
        response = requests.get('https://host.io/api/full/' + host_name + '?token=' + self.token)
        data = response.json()

        if response.status_code != 200:
            print(response.status_code + "\n")
            pprint.pprint(data)
            return None

        if ret_json:
            return data

        #return jsonToString(data)
        return jsonFlatten(data)

class ThreatCrowd:
    def lookup_ip(self, ip_addr, ret_json=False):
        url = 'http://www.threatcrowd.org/searchApi/v2/ip/report/'
        req_params = {'ip': ip_addr}

        response = requests.get(url, params=req_params)
        data = response.json()

        if response.status_code != 200:
            print(response.status_code + "\n")
            pprint.pprint(data)
            return None

        if ret_json:
            return data

        #return jsonToString(data)
        return jsonFlatten(data)
