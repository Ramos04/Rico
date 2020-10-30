import os
import pprint
import requests
import json
from  functools import reduce
from rico.util.parse import Parse
from rico.util.debug import Debug

class IP():
    @staticmethod
    def recon(tokens, target):
        # keys  : recon service
        # value : dict of results for that service
        return_dict = {}

        # call greynoise recon and append to dict
        return_dict['greynoise'] = IP._greynoise(tokens['greynoise'], target)
        return_dict['ipinfo'] = IP._ipinfo(tokens['ipinfo'], target)
        return_dict['abuseipdb'] = IP._abuseipdb(tokens['abuseipdb'], target)

        return return_dict

    #########################################
    #               Greynoise
    #########################################
    @staticmethod
    def _greynoise(token, target):
        results_dict = {}
        key_dict = {
            'IP Address'        : 'ip',
            'Classification'    : 'classification',
            'Actor'             : 'actor',
            'First Seen'        : 'first_seen',
            'Last Seen'         : 'last_seen',
            'ASN'               : 'metadata.asn',
            'Category'          : 'metadata.category',
            'City'              : 'metadata.city',
            'Country'           : 'metadata.country',
            'Organization'      : 'metadata.organization',
            'OS'                : 'metadata.os',
            'RDNS'              : 'metadata.rdns',
            'Region'            : 'metadata.region',
            'Spoofable'         : 'metadata.spoofable',
            'TOR'               : 'metadata.tor',
            'VPN'               : 'metadata.vpn',
            'VPN Service'       : 'metadata.vpn_service',
            'Scan Info'         : 'raw_data.scan',
            'Web'               : 'raw_data.web',
            'Seen'              : 'seen',
            'Spoofable'         : 'spoofable',
            'Tags'              : 'tags'
            }

        url = 'https://api.greynoise.io/v2/noise/context/' + target
        headers = {
            'accept': 'application/json',
            'key': token
        }

        response = requests.request("GET", url, headers=headers)

        if response.status_code == 200:
            data = response.json()

            for key, value in key_dict.items():
                results_dict[key] = Parse.get_dict_safe(data, value)

        return results_dict

    #########################################
    #               IPInfo
    #########################################
    @staticmethod
    def _ipinfo(token, target):
        results_dict = {}
        key_dict = {
            'City'          : 'city',
            'Country'       : 'country',
            'IP Address'    : 'ip',
            'Coordinates'   : 'loc',
            'Organization'  : 'org',
            'Region'        : 'region',
            'Timezone'      : 'timezone'
            }

        url = 'https://ipinfo.io/' + target + '?token=' + token
        headers = {'accept': 'application/json'}

        response = requests.request("GET", url)

        if response.status_code == 200:
            data = response.json()

            for key, value in key_dict.items():
                results_dict[key] = Parse.get_dict_safe(data, value)

        return results_dict
    #########################################
    #               AbuseIPDB
    #########################################
    @staticmethod
    def _abuseipdb(token, target):
        results_dict = {}
        key_dict = {
            'IP Address'    : 'data.ipAddress',
            'Confidence'    : 'data.abuseConfidenceScore',
            'Domain'        : 'data.domain',
            'Usage Type'    : 'data.usageType',
            'Total Reports' : 'data.totalReports',
            'Last Report'   : 'data.lastReportedAt',
            'Public'        : 'data.isPublic',
            'Whitelisted'   : 'data.isWhitelisted',
            'Hostnames'     : 'data.hostnames',
            'User Count'    : 'data.numDistinctUsers'
            }

        url = 'https://api.abuseipdb.com/api/v2/check'

        querystring = {
            'ipAddress': target,
            'maxAgeInDays': '90'
        }

        headers = {
            'Accept': 'application/json',
            'Key': token
        }

        response = requests.request(method='GET', url=url, headers=headers, params=querystring)

        if response.status_code == 200:
            data = response.json()

            for key, value in key_dict.items():
                results_dict[key] = Parse.get_dict_safe(data, value)

        return results_dict
