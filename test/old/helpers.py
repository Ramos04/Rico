import os
import requests
import json
import pprint

################################################################################
#                                   MalwareBazaar
################################################################################
class MalwareBazaar:
    def __init__ (self):
        self.token = 'token'

    def lookup_domain(self, file_hash):
        print(file_hash)
        url = 'https://mb-api.abuse.ch/api/v1/'

        query = {
            'query': 'get_info',
            'hash': file_hash
        }

        response = requests.post(url, data=query, timeout=15)

        if response.status_code == 200:
            data = response.json()

            return data

        return False

################################################################################
#                                   HostIO
################################################################################
class Hostio:
    def __init__ (self, token):
        self.token = token

    def lookup_domain(self, host_name, ret_json=False):
        response = requests.get('https://host.io/api/full/' + host_name + '?token=' + self.token)
        data = response.json()

        print("+---------------+\n|    HOSTIO     |\n+---------------+")
        pprint.pprint(data)
        print("\n")
        pprint.pprint(data)

################################################################################
#                                   IPInfo
################################################################################
class IPinfo:
    def __init__ (self, token):
        self.token = token
        self.results_dict = {}

    def lookup_ip(self, ip_addr):
        self._make_request(ip_addr)
        self._print_results()

    def lookup_ip_dict(self, ip_addr):
        self._make_request(ip_addr)

        return self.results_dict

    def _make_request(self, ip_addr):
        url = 'https://ipinfo.io/' + ip_addr + '?token=' + self.token
        headers = {'accept': 'application/json'}

        response = requests.request("GET", url)

        if response.status_code == 200:
            data = response.json()

            self.results_dict['City'] = data['city']
            self.results_dict['Country'] = data['country']
            self.results_dict['IP Address'] = data['ip']
            self.results_dict['Coordinates'] = data['loc']
            self.results_dict['Organization'] = data['org']
            self.results_dict['Region'] = data['region']
            self.results_dict['Timezone'] = data['timezone']

            return True

        return False

    def _print_results(self):
        print('+----------------------------+')
        print('| {:^26} |'.format('IPInfo'))
        print('+----------------------------+')

        if self.results_dict:
            for key, value in self.results_dict.items():
                print('{:15} : {}'.format(key, value))

################################################################################
#                                   AbuseIPDB
################################################################################
class Abuseipdb:
    def __init__ (self, token):
        self.token = token
        self.results_dict = {}

    def lookup_ip(self, ip_addr):
        self._make_request(ip_addr)
        #self._print_results()

    def _make_request(self, ip_addr):
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

        if response.status_code == 200:
            data = response.json()

            self.results_dict['IP Address'] = data['data']['ipAddress']
            self.results_dict['Confidence'] = data['data']['abuseConfidenceScore']
            self.results_dict['Domain'] = data['data']['domain']
            self.results_dict['Usage Type'] = data['data']['usageType']
            self.results_dict['Total Reports'] = data['data']['totalReports']
            self.results_dict['Last Report'] = data['data']['lastReportedAt']
            self.results_dict['Public'] = data['data']['isPublic']
            self.results_dict['Whitelisted'] = data['data']['isWhitelisted']
            self.results_dict['Hostnames'] = data['data']['hostnames']
            self.results_dict['User Count'] = data['data']['numDistinctUsers']

            return True

        return False
    """
    def _print_results(self):
        print('+----------------------------+')
        print('| {:^26} |'.format('AbuseIP DB'))
        print('+----------------------------+')

        if self.results_dict:
            for key, value in self.results_dict.items():
                if type(value) is list:
                    print('{:15} :'.format(key))
                    for item in value:
                            print(('    {}'.format(item)))
                else:
                    print('{:15} : {}'.format(key, value))
    """
################################################################################
#                                   GreyNoise
################################################################################
class Greynoise:
    def __init__ (self, token):
        self.token = token
        self.results_dict = {}

    def lookup_ip(self, ip_addr):
        self._make_request(ip_addr)
        self._print_results()

    def lookup_ip_dict(self, ip_addr):
        self._make_request(ip_addr)

        return self.results_dict

    def _make_request(self, ip_addr):
        url = 'https://api.greynoise.io/v2/noise/context/' + ip_addr
        headers = {
            'accept': 'application/json',
            'key': self.token
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

    def _print_results(self):
        print('+----------------------------+')
        print('| {:^26} |'.format('GreyNoise'))
        print('+----------------------------+')

        if self.results_dict:
            for k1, v1 in self.results_dict.items():

                if type(v1) is list:
                    print('{:15} :'.format(k1))
                    for item in v1:
                        if type(item) is dict:
                            for k2, v2 in item.items():
                                print(('    {:5} : {}'.format(k2, v2)))
                        else:
                            print(('    {}'.format(item)))
                elif type(v1) is dict:
                    print('{:15} :'.format(k1))
                    for k2, v2 in v1.items():
                        print(('    {:11} :'.format(k2)))
                        if type(v2) is list:
                            for item in v2:
                                print(('         {}'.format(item)))
                        else:
                            print(('    {:5} : {}'.format(k2, v2)))
                else:
                    print('{:15} : {}'.format(k1, v1))

################################################################################
#                                SecurityTrails
################################################################################

################################################################################
#                                  Shodan
################################################################################

################################################################################
#                               Hybrid Analysis
################################################################################

################################################################################
#                               ThreatCrowd
################################################################################
