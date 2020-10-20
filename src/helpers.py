import os
import requests
import json
import pprint

class Abuseipdb:
    def __init__ (self, token):
        self.token = token

    def lookup_ip(self, ip_addr):
        url = 'https://api.abuseipdb.com/api/v2/check'

        querystring = {
            'ipAddress': ip_addr,
            'maxAgeInDays': '90'
        }

        headers = {
            'Accept': 'application/json',
            'Key': self.token
        }

        response = requests.request(method='GET', url=url, headers=headers, params=querystring)

        data = response.json()

        print("+---------------+\n|   ABUSEIPDB   |\n+---------------+")
        pprint.pprint(data)
        print("\n")


class Greynoise:
    def __init__ (self, token):
        self.token = token

    def lookup_ip(self, ip_addr):
        url = 'https://api.greynoise.io/v2/noise/context/' + ip_addr
        headers = {
            'accept': 'application/json',
            'key': self.token
        }

        response = requests.request("GET", url, headers=headers)

        data = response.json()

        print("+---------------+\n|   GREYNOISE   |\n+---------------+")
        pprint.pprint(data)
        print("\n")

class HybridAnalysis:
    def __init__ (self, token):
        self.token = token

class Hostio:
    def __init__ (self, token):
        self.token = token

    def lookup_domain(self, host_name, ret_json=False):
        response = requests.get('https://host.io/api/full/' + host_name + '?token=' + self.token)
        data = response.json()

        pprint.pprint(data)

class IPinfo:
    def __init__ (self, token):
        self.token = token

    def lookup_ip(self, ip_addr, ret_json=False):
        url = 'https://ipinfo.io/' + ip_addr + '?token=' + self.token
        #headers = {'accept': 'application/json'}

        response = requests.request("GET", url)
        data = response.json()

        print("+--------------+\n|    IP INFO   |\n+--------------+")
        pprint.pprint(data)
        print("\n")

class SecurityTrails:
    def __init__ (self, token):
        self.token = token

    def dns_history(self, domain):
        import requests

        url = 'https://api.securitytrails.com/v1/history/' + domain + '/dns/a'

        headers = {
            'accept': 'application/json',
            'apikey': self.token
        }

        response = requests.request('GET', url, headers=headers)
        data = response.json()

        print('+--------------------+\n|   SecurityTrails   |\n +--------------------+')
        pprint.pprint(data)
        print('\n')

    def history_whois(self, domain):
        url = 'https://api.securitytrails.com/v1/history/securitytrails.com/whois'
        headers = {'apikey': self.token}

        response = requests.request('GET', url, headers=headers)
        data = response.json()

        print('+--------------------+\n|   SecurityTrails   |\n +--------------------+')
        pprint.pprint(data)
        print('\n')

    def domain_details(self, domain)
        url = 'https://api.securitytrails.com/v1/domain/' + domain
        headers = {
            'accept': 'application/json',
            'apikey': self.token
        }

        response = requests.request('GET', url, headers=headers)
        data = response.json()

        print('+--------------------+\n|   SecurityTrails   |\n +--------------------+')
        pprint.pprint(data)
        print('\n')

    def domain_subdomains(self, domain)
        data = response.json()
        url = 'https://api.securitytrails.com/v1/domain/' + domain '/subdomains'

        querystring = {'children_only':'false'}

        headers = {
            'accept': 'application/json',
            'apikey': self.token
        }

        response = requests.request('GET', url, headers=headers, params=querystring)
        data = response.json()

        print('+--------------------+\n|   SecurityTrails   |\n +--------------------+')
        pprint.pprint(data)
        print('\n')

    def domain_tags(self, domain):
        url = 'https://api.securitytrails.com/v1/domain/oracle.com/tags'
        headers = {
            'accept': 'application/json',
            'apikey': self.token
        }

        response = requests.request('GET', url, headers=headers)
        data = response.json()

        print('+--------------------+\n|   SecurityTrails   |\n +--------------------+')
        pprint.pprint(data)
        print('\n')

class ThreatCrowd:
    def lookup_ip(self, ip_addr, ret_json=False):
        url = 'http://www.threatcrowd.org/searchApi/v2/ip/report/'
        req_params = {'ip': ip_addr}

        response = requests.get(url, params=req_params)
        data = response.json()

        pprint.pprint(data)
