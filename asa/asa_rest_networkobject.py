#!/usr/bin/env python2.7

# Copyright (c) 2017 Sybil Melton, Dominion Enterprises
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
# Extends RASA module written by Patrick Ogenstad <patrick@ogenstad.com> https://github.com/networklore/rasa

DOCUMENTATION = '''
---

module: asa_rest_networkobject
short_description: Log in to an ASA with REST API
description:
    - Offers ability to log in to an ASA with the REST API and retrieve serial number to verify connectivity and functionality
author: Sybil Melton
requirements:
    - ASA REST 1.3
options:
    type:
        description:
            - The type of object you are creating. Use slash notation for subnets, i.e. 192.168.0.0/24. Use - for ranges, i.e. 192.168.0.1-192.168.0.10. 
        choices: [ 'ipv4_address', 'ipv6_address', 'ipv4_subnet', 'ipv6_subnet', 'ipv4_range', 'ipv6_range', 'ipv4_fqdn', 'ipv6_fqdn' ]
        required: false
    description:
        description:
            - Description of the object
        required: false
    host:
        description:
            - IP or hostname of the ASA
        required: true
    name:
        description:
            - Name of the network object
        required: true
    password:
        description:
            - Password for the device
        required: true
    state:
        description:
            - State of the object
        choices: [ 'present', 'absent' ]
        required: true
    username:
        description:
            - Username for device
        required: true
    validate_certs:
        description:
            - If False, SSL certificates will not be validated. This should only be used on personally controlled sites using self-signed certificates.
        choices: [ True, False]
        default: True
        required: false
    value:
        description:
            - The data to enter into the network object
        required: false
'''
EXAMPLES = '''
- asa_rest_networkobject:
    host={{ ansible_host }}
    username=api_user
    password=APIpass123
    name=WEB1_10.12.30.10
    state=present
    type=ipv4_address
    description='Test web server'
    value='10.12.30.10'
    validate_certs=False
- asa_rest_networkobject:
    host={{ ansible_host }}
    username=api_user
    password=APIpass123
    name=WEB1_10.12.30.10
    state=absent
    validate_certs=False
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
    sample: "result": { "kind": "object#QuerySerialNumber", "serialNumber": "9AFMQXLC3TS"}
'''
import urllib3
import logging
from ansible.module_utils.basic import *
import requests
import json
import sys
from requests.auth import HTTPBasicAuth

requests.packages.urllib3.disable_warnings()

HEADERS = {
    'Content-Type': 'application/json',
    'Accept': 'application/json',
    'User-Agent': 'ANSIBLE'
}

object_kind = {
    'ipv4_address': 'IPv4Address',
    'ipv6_address': 'IPv6Address',
    'ipv4_subnet': 'IPv4Network',
    'ipv6_subnet': 'IPv6Network',
    'ipv4_range': 'IPv4Range',
    'ipv6_range': 'IPv6Range',
    'ipv4_fqdn': 'IPv4FQDN',
    'ipv6_fqdn': 'IPv6FQDN'
}

class ASA(object):

    def __init__(self, device=None, username=None, password=None, verify_cert=True, timeout=5):
        
        self.device = device
        self.username = username
        self.password = password
        self.verify_cert = verify_cert
        self.timeout = timeout
        self.cred = HTTPBasicAuth(self.username, self.password)

    ######################################################################
    # General Functions
    ######################################################################
    def _delete(self, request):
        url = 'https://' + self.device + '/api/' + request
        data = requests.delete(url,headers=HEADERS,auth=self.cred, verify=self.verify_cert, timeout=self.timeout)
        return data

    def _get(self, request):
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
    # <OBJECTS>
    ######################################################################
    # Functions related to network objects, or "object network" in the
    # ASA configuration
    ######################################################################
    def create_networkobject(self, data):
        request = 'objects/networkobjects'
        return self._post(request, data)

    def delete_networkobject(self, net_object):
        request = 'objects/networkobjects/' + net_object
        return self._delete(request)

    def get_networkobject(self, net_object):
        request = 'objects/networkobjects/' + net_object
        return self._get(request)

    def get_networkobjects(self):
        request = 'objects/networkobjects'
        return self._get(request)

    #def get_networkservices(self):
    #    request = 'objects/predefinednetworkservices'
    #    return self._get(request)

    def update_networkobject(self, name, data):
        request = 'objects/networkobjects/' + name
        return self._put(request, data)


    ######################################################################
    # Functions related to specific commands
    ######################################################################
    def write_mem(self):
        """Saves the running configuration to memory
        """
        request = 'commands/writemem'
        return self._post(request)

urllib3.disable_warnings()
logging.captureWarnings(True)

def match_objects(current_data, desired_data, module):
    has_current_desc = False
    has_desired_desc = False
    
    if 'description' in current_data.keys():
        has_current_desc = True
    
    if 'description' in desired_data.keys():
        has_desired_desc = True
    
    if has_current_desc == has_desired_desc:
        if has_desired_desc == True:
            if current_data['description'] != desired_data['description']:
                return False
    else:
        return False
    
    if current_data['host'] != desired_data['host']:
        return False
    return True

def update_object(dev, module, desired_data):
    try:
        before = dev.get_networkobject(desired_data['name'])
        result = dev.update_networkobject(desired_data['name'], desired_data)
    except:
        err = sys.exc_info()[0]
        module.fail_json(msg='Unable to connect to device: %s' % err)
    
    if result.status_code == 204:
        data = dev.get_networkobject(desired_data['name'])
        return_status = { 'changed': True, 'previous': before.json(), 'result': data.json() }
    else:
        module.fail_json(msg='Unable to update object code: - %s' % result.status_code)
    
    return return_status

def create_object(dev, module, desired_data):
    try:
        result = dev.create_networkobject(desired_data)
    except:
        err = sys.exc_info()[0]
        module.fail_json(msg='Unable to connect to device: %s' % err)

    if result.status_code == 201:
        data = dev.get_networkobject(desired_data['name'])
        return_status = { 'changed': True, 'result': data.json() }
    else:
        module.fail_json(msg='Unable to create object - %s' % result.status_code)

    return return_status

def delete_object(dev, module, name):
    try:
        before = dev.get_networkobject(name)
        result = dev.delete_networkobject(name)
    except:
        err = sys.exc_info()[0]
        module.fail_json(msg='Unable to connect to device: %s' % err)

    if result.status_code == 204:
        return_status = { 'previous': before.json(), 'changed': True }
    else:
        module.fail_json(msg='Unable to delete object - %s' % result.status_code)

    return return_status

def main():
    
    module = AnsibleModule(
        argument_spec=dict(
            host=dict(required=True),
            username=dict(required=True),
            password=dict(required=True),
            validate_certs=dict(required=False, choices=[True, False], default=True),
            provider=dict(required=False),
            name=dict(required=True),
            description=dict(required=False),
            state=dict(required=True, choices=['absent', 'present']),
            type=dict(required=False, choices=[ 'ipv4_address', 'ipv6_address', 'ipv4_subnet', 'ipv6_subnet', 'ipv4_range', 'ipv6_range', 'ipv4_fqdn', 'ipv6_fqdn' ]),
            value=dict(required=False)),
            required_together = ( ['type','value'],
        ),
        supports_check_mode=False
    )
    
    name = module.params['name']
    objectId = module.params['name']
    type = module.params['type']
    value = module.params['value']
    state = module.params['state']
    
    if state == "present":
        if type == False:
            module.fail_json(msg='Category not defined')
    
    dev = ASA(
        username = module.params['username'],
        password = module.params['password'],
        device = module.params['host'],
        verify_cert = module.params['validate_certs']
    )
    
    
    desired_data = {}
    desired_data['name'] = name
    desired_data['objectId'] = objectId
    desired_data['kind'] = 'object#NetworkObj'
    if type:
        kind = object_kind[type]
        desired_data['host'] = {
            'kind': kind,
            'value': value
        }
    
    if module.params['description']:
        desired_data['description'] = module.params['description']
    
    try:
        data = dev.get_networkobject(name)
    except:
        err = sys.exc_info()[0]
        module.fail_json(msg='Unable to connect to device: %s' % err)
    
    if data.status_code == 200:
        if state == 'absent':
            changed_status = delete_object(dev, module, name)
        elif state == 'present':
            matched = match_objects(data.json(), desired_data, module)
            if matched:
                changed_status = {'changed': False, 'result': data.json()} 
            else:
                changed_status = update_object(dev, module, desired_data)
    
    elif data.status_code == 401:
        module.fail_json(msg='Authentication error')
    
    elif data.status_code == 404:
        if state == 'absent':
            changed_status = {'changed': False, 'result': data.json()} 
        elif state == 'present':
            changed_status = create_object(dev, module, desired_data)
    else:
        module.fail_json(msg="Unsupported return code %s" % data.status_code)
    
    module.exit_json(**changed_status)
    
main()
