#!/usr/bin/env python2.7
from lib2to3.fixes.fix_input import context

# Copyright (c) 2017 Sybil Melton, Dominion Enterprises
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
# Extends RASA module written by Patrick Ogenstad <patrick@ogenstad.com> https://github.com/networklore/rasa

DOCUMENTATION = '''
---

module: asa_rest_arp
short_description: Log in to an ASA with REST API and get the arp cache
description:
    - Offers ability to log in to an ASA with the REST API and retrieve the arp cache
author: Sybil Melton
requirements:
    - ASA REST 1.3
options:
    validate_certs:
        description:
            - Dictates whether the ASA certificate will be validated
        required: false
        default: True
        choices: [True, False]
        aliases: []
    context:
        description:
            - The ASA context if needed
        required: false
        default: null
        choices: []
        aliases: []
    interface:
        description:
            - return only ARP for a certain interface
        required: false
        default: null
        choices: []
        aliases: []
'''
EXAMPLES = '''
asa_rest_login: host={{ ansible_host }} username='admin' password='C1sco123' validate_certs=False
'''
RETURN = '''
changed:
    description:  Returns the status code
    returned: True
    type: string
    sample: true
result:
    description:  Returns the json
    returned: True
    type: string
    sample: "result": {"arps": [{"interface": "inside", "ipAddress": "10.3.6.6", "macAddress": "0050.5698.7777", "proxyArp": false}, {"interface": "inside", "ipAddress": "10.9.6.10", "macAddress": "0050.5698.1010", "proxyArp": false}], "total": 2}
'''
import urllib3
import logging
from ansible.module_utils.basic import *
import requests
import json
import sys
from requests.auth import HTTPBasicAuth
import time
from ansible.module_utils.network.asa.asa import asa_argument_spec
from netaddr import *

requests.packages.urllib3.disable_warnings()

HEADERS = {
    'Content-Type': 'application/json',
    'Accept': 'application/json',
    'User-Agent': 'ANSIBLE'
}

class ASA(object):

    def __init__(self, device=None, username=None, password=None, verify_cert=True, timeout=10, context=None):
        
        self.device = device
        self.username = username
        self.password = password
        self.verify_cert = verify_cert
        self.timeout = timeout
        self.context = context
        self.cred = HTTPBasicAuth(self.username, self.password)
        
    def context_set(self):
        if self.context:
            return True
        return False
    ######################################################################
    # General Functions
    ######################################################################
    def _delete(self, request):
        url = 'https://' + self.device + '/api/' + request
        data = requests.delete(url,headers=HEADERS,auth=self.cred, verify=self.verify_cert, timeout=self.timeout)
        return data

    def _get(self, request, offset, limit):
        if self.context_set():
            payload = {'context': self.context, 'offset': offset, 'limit': limit}
            url = 'https://' + self.device + '/api/' + request
            data = requests.get(url,headers=HEADERS,auth=self.cred, verify=self.verify_cert, timeout=self.timeout, params=payload)
        else:
            url = 'https://' + self.device + '/api/' + request
            data = requests.get(url,headers=HEADERS,auth=self.cred, verify=self.verify_cert, timeout=self.timeout)
        
        return data

    def _patch(self, request, data):
        url = 'https://' + self.device + '/api/' + request
        data = requests.patch(url, data=json.dumps(data), headers=HEADERS, auth=self.cred, verify=self.verify_cert, timeout=self.timeout)
        return data

    def _post(self, request, data=False):
        url = 'https://' + self.device + '/api/' + request
        if data != False:
            data = requests.post(url, data=json.dumps(data), headers=HEADERS, auth=self.cred, verify=self.verify_cert, timeout=self.timeout)
        else:
            data = requests.post(url, headers=HEADERS, auth=self.cred, verify=self.verify_cert, timeout=self.timeout)            
        return data

    def _put(self, request, data):
        url = 'https://' + self.device + '/api/' + request
        data = requests.put(url, data=json.dumps(data), headers=HEADERS, auth=self.cred, verify=self.verify_cert, timeout=self.timeout)
        return data

    ######################################################################
    # </VPN>
    ######################################################################

    ######################################################################
    # Functions related to specific commands
    ######################################################################
    def write_mem(self):
        """Saves the running configuration to memory
        """
        request = 'commands/writemem'
        return self._post(request)
    
    def get_arp(self, offset, limit):
        request = 'monitoring/arp'
        return self._get(request, offset, limit)

urllib3.disable_warnings()
logging.captureWarnings(True)

def main():

    spec = dict(
        # { command: <str>, prompt: <str>, response: <str> }
        validate_certs=dict(choices=[True, False], default=True),
        retries=dict(default=3, type='int'),
        interval=dict(default=1, type='int'),
        context=dict(required=False),
        limit=dict(default=100, type='int'),
        interface=dict(required=False),
        network=dict(required=False)
    )
    
    spec.update(asa_argument_spec)
    module = AnsibleModule(argument_spec=spec, supports_check_mode=False)
    
    result = {}
    retries = module.params['retries']
    interval = module.params['interval']
    limit = module.params['limit']
    interface = module.params['interface']
    network = module.params['network']
    
    dev = ASA(
        username = module.params['provider']['username'],
        password = module.params['provider']['password'],
        device = module.params['provider']['host'],
        context = module.params['context'],
        verify_cert = module.params['validate_certs']
    )
    arps = []
    offset = 0
    while retries > 1:
        try:
            int = dev.get_arp(offset, limit)
            if int.status_code == 200:
                return_status = True
                total = int.json()['rangeInfo']['total']
                
                arps += int.json()['items']
                if total > limit:
                    offset += limit
                    while total - offset > 100:
                        rem = dev.get_arp(offset, limit)
                        offset += limit
                        arps += rem.json()['items']
                    last = dev.get_arp(offset, limit)
                    arps += last.json()['items']
            elif data.status_code == 401:
                module.fail_json(msg='Authentication error')
            else:
                module.fail_json(msg='Unable to retrieve arp: - %s' % int.status_code)
            break
        except:
            err = sys.exc_info()[0]
            time.sleep(interval)
        retries -= 1
    
    if retries == 1:
        try:
            int = dev.get_arp(offset, limit)
            if int.status_code == 200:
                return_status = True
                total = int.json()['rangeInfo']['total']
                arps += int.json()['items']
                if total > limit:
                    offset += limit
                    while total - offset > 100:
                        rem = dev.get_arp(offset, limit)
                        offset += limit
                        arps += rem.json()['items']
                    offset += limit
                    last = dev.get_arp(offset, limit)
                    arps += last.json()['items']
            elif data.status_code == 401:
                module.fail_json(msg='Authentication error')
            else:
                module.fail_json(msg='Unable to retrieve arp: - %s' % int.status_code)
        except:
            err = sys.exc_info()[0]
            module.fail_json(msg='Unable to connect to device: %s' % err)
    
    if len(arps) != total:
        module.fail_json(msg='failed to retrieve all arps')
    
    if network:
        matchingarps = filter(lambda a: IPAddress(a['ipAddress']) in IPNetwork(network), arps) 
        result['arps'] = matchingarps
        result['total'] = len(matchingarps)
    elif interface:
        matchingarps = filter(lambda a: a['interface'] == interface, arps) 
        result['arps'] = matchingarps
        result['total'] = len(matchingarps)
    else:
        result['arps'] = arps
        result['total'] = len(arps)

    return_msg = { 'result': result, 'changed': return_status } 
    module.exit_json(**return_msg)
    
main()
