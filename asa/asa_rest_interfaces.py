#!/usr/bin/env python2.7
from lib2to3.fixes.fix_input import context

# Copyright (c) 2017 Sybil Melton, Dominion Enterprises
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
# Extends RASA module written by Patrick Ogenstad <patrick@ogenstad.com> https://github.com/networklore/rasa

DOCUMENTATION = '''
---

module: asa_rest_interfaces
short_description: Log in to an ASA with REST API
description:
    - Offers ability to log in to an ASA with the REST API and retrieve interface statistics
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
    sample: "result": { "interfaces": "items": [], "kind": "collection#MonitoringMetric", "rangeInfo": {"limit": 24, "offset": 0, "total": 24}, "selfLink": "https://10.9.4.1/api/monitoring/device/interfaces?context=ABC"}
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

    def _get(self, request):
        if self.context_set():
            payload = {'context': self.context}
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
    
    def get_interfaces(self):
        request = 'monitoring/device/interfaces'
        return self._get(request)

urllib3.disable_warnings()
logging.captureWarnings(True)

def main():

    spec = dict(
        # { command: <str>, prompt: <str>, response: <str> }
        validate_certs=dict(choices=[True, False], default=True),
        retries=dict(default=3, type='int'),
        interval=dict(default=1, type='int'),
        context=dict(required=False)
    )
    
    spec.update(asa_argument_spec)
    module = AnsibleModule(argument_spec=spec, supports_check_mode=True)
    
    result = {}
    retries = module.params['retries']
    interval = module.params['interval']
    
    dev = ASA(
        username = module.params['provider']['username'],
        password = module.params['provider']['password'],
        device = module.params['provider']['host'],
        context = module.params['context'],
        verify_cert = module.params['validate_certs']
    )
    
    while retries > 1:
        try:
            int = dev.get_interfaces()
            break
        except:
            err = sys.exc_info()[0]
            time.sleep(interval)
        retries -= 1
    
    if retries == 1:
        try:
            int = dev.get_interfaces()
        except:
            err = sys.exc_info()[0]
            module.fail_json(msg='Unable to connect to device: %s' % err)
    
    if int.status_code == 200:
        return_status = True
        result['interfaces'] = int.json()
    else:
        module.fail_json(msg='Unable to retrieve version: - %s' % int.status_code)

    return_msg = { 'result': result, 'changed': return_status } 
    module.exit_json(**return_msg)
    
main()
