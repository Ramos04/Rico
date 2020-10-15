#!/usr/bin/env python3

import os
import requests
import json

class Greynoise:

    def __init__(self, token, info_type, info):
        self._token = token
        self._info_type = info_type

        if info_type == "ip":
            self._json = self.request_ip(info)

    def request_ip(self, ip_addr):
        url = "http://www.threatcrowd.org/searchApi/v2/ip/report/"
        req_params = {"ip": ip_addr}

        response = requests.get(url, params=req_params)

        data = response.json()

        return data

    def dump(self):
        return self._json
