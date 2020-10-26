import os
import requests
import json

class IP():
    def __init__(self, targets, tokens):

    def request(targets)

        for target in targets:
            greynoise(tokens['greynoise'], target)

def greynoise(token, targets):
        url = 'https://api.greynoise.io/v2/noise/context/' + ip_addr
        headers = {
            'accept': 'application/json',
            'key': token
        }

        response = requests.request("GET", url, headers=headers)

        if response.status_code == 200:
            data = response.json()

            self.results_dict['IP Address'] = data['ip']
            self.results_dict['Classification'] = data['classification']
            self.results_dict['Actor'] = data['actor']
            self.results_dict['First Seen'] = data['first_seen']
            self.results_dict['Last Seen'] = data['last_seen']
            self.results_dict['ASN'] = data['metadata']['asn']
            self.results_dict['Category'] = data['metadata']['category']
            self.results_dict['City'] = data['metadata']['city']
            self.results_dict['Country'] = data['metadata']['country']
            self.results_dict['Organization'] = data['metadata']['organization']
            self.results_dict['OS'] = data['metadata']['os']
            self.results_dict['RDNS'] = data['metadata']['rdns']
            self.results_dict['Region'] = data['metadata']['region']
            self.results_dict['Spoofable'] = data['metadata']['spoofable']
            self.results_dict['TOR'] = data['metadata']['tor']
            self.results_dict['VPN'] = data['metadata']['vpn']
            self.results_dict['VPN Service'] = data['metadata']['vpn_service']
            self.results_dict['Scan Info'] = data['raw_data']['scan']
            self.results_dict['Web'] = data['raw_data']['web']
            self.results_dict['Seen'] = data['seen']
            self.results_dict['Spoofable'] = data['spoofable']
            self.results_dict['Tags'] = data['tags']

            return True

        return False

