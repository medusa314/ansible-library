#!/usr/bin/env python2.7

# Copyright (c) 2017 Sybil Melton, Dominion Enterprises
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = '''
---

module: asa_rest_login
short_description: Log in to an ASA with REST API
description:
    - Offers ability to log in to an ASA with the REST API and retrieve serial number to verify connectivity and functionality
author: Sybil Melton
requirements:
    - ASA REST 1.3
options:
    host:
        description:
            - IP Address or hostname of ASA resolvable by Ansible control host
        required: true
        default: null
        choices: []
        aliases: []
    username:
        description:
            - Username used to login to the firewall
        required: true
        default: null
        choices: []
        aliases: []
    password:
        description:
            - Password used to login to the firewall
        required: true
        default: null
        choices: []
        aliases: []
    validate_certs:
        description:
            - Dictates whether the ASA certificate will be validated
        required: false
        default: https
        choices: [True, False]
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
    # Unsorted functions
    ######################################################################
    def get_access_in(self):
        request = 'access/in'
        return self._get(request)

    def get_acl_ace(self, acl):
        request = 'objects/extendedacls/' + acl + '/aces'
        return self._get(request)

    def get_acls(self):
        request = 'objects/extendedacls'
        return self._get(request)

    def get_localusers(self):
        request = 'objects/localusers'
        return self._get(request)

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
    # Functions related to network object-groups, or
    # "object-group network" in the ASA configuration
    ######################################################################

    def add_member_networkobjectgroup(self, net_object, member_data):
        request = 'objects/networkobjectgroups/' + net_object
        data = {}
        data['members.add'] = member_data
        return self._patch(request, data)

    def create_networkobjectgroup(self, data):
        request = 'objects/networkobjectgroups'
        return self._post(request, data)

    def delete_networkobjectgroup(self, net_object):
        request = 'objects/networkobjectgroups/' + net_object
        return self._delete(request)

    def get_networkobjectgroup(self, net_object):
        request = 'objects/networkobjectgroups/' + net_object
        return self._get(request)

    def get_networkobjectgroups(self):
        request = 'objects/networkobjectgroups'
        return self._get(request)

    def remove_member_networkobjectgroup(self, net_object, member_data):
        request = 'objects/networkobjectgroups/' + net_object
        data = {}
        data['members.remove'] = member_data
        return self._patch(request, data)

    def update_networkobjectgroup(self, net_object, data):
        request = 'objects/networkobjectgroups/' + net_object
        return self._patch(request, data)


    ######################################################################
    # Functions related to service objects, or "object service" in the
    # ASA configuration
    ######################################################################
    def create_serviceobject(self, data):
        request = 'objects/networkservices'
        return self._post(request, data)

    def delete_serviceobject(self, svc_object):
        request = 'objects/networkservices/' + svc_object
        return self._delete(request)

    def get_serviceobject(self, svc_object):
        request = 'objects/networkservices/' + svc_object
        return self._get(request)

    def get_serviceobjects(self):
        request = 'objects/networkservices'
        return self._get(request)

    def update_serviceobject(self, name, data):
        request = 'objects/networkservices/' + name
        return self._patch(request, data)


    ######################################################################
    # </OBJECTS>
    ######################################################################

    ######################################################################
    # <VPN>
    ######################################################################
    # Functions related to network objects, or "object network" in the
    # ASA configuration
    ######################################################################

    def create_ikev1_policy(self, data):
        request = 'vpn/ikev1policy'
        return self._post(request, data)

    def delete_ikev1_policy(self, policy):
        request = 'vpn/ikev1policy/' + policy
        return self._delete(request)

    def get_ikev1_policies(self):
        request = 'vpn/ikev1policy'
        return self._get(request)

    def get_ikev1_policy(self, policy):
        request = 'vpn/ikev1policy/' + policy
        return self._get(request)

    def update_ikev1_policy(self, policy, data):
        request = 'vpn/ikev1policy/' + policy
        return self._patch(request, data)


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
    
    def get_serial(self):
        request = 'monitoring/serialnumber'
        return self._get(request)
    
def asa_login(host, user, password):
    """Login to ASA"""
    if not host.startswith(('http', 'https')):
        host = 'https://' + host
    headers = {'Content-Type': 'application/json'}
    api_path = "/api/"
    url = server + api_path
    f = None
    req = urllib2.Request(url, None, headers)
    base64string = base64.encodestring('%s:%s' % (user, password)).replace('\n', '')
    req.add_header("Authorization", "Basic %s" % base64string)
    try:
        f = urllib2.urlopen(req)
        status_code = f.getcode()
        if (status_code != 200):
            print 'Error in get. Got status code: '+ status_code
        resp = f.read()
        json_resp = json.loads(resp)
        moDir = json.dumps(json_resp,sort_keys=True,indent=4, separators=(',', ': '))
    finally:
        if f:  f.close()
    
    return moDir

urllib3.disable_warnings()
logging.captureWarnings(True)

def main():

    module = AnsibleModule(
        argument_spec=dict(
            host=dict(required=True),
            username=dict(required=True),
            password=dict(required=True),
            validate_certs=dict(required=False, choices=[True, False], default=True),
            provider=dict(required=False)
        ),
        supports_check_mode=False
    )
    
    dev = ASA(
        username = module.params['username'],
        password = module.params['password'],
        device = module.params['host'],
        verify_cert = module.params['validate_certs']
    )

    try:
        data = dev.get_serial()
    except:
        err = sys.exc_info()[0]
        module.fail_json(msg='Unable to connect to device: %s' % err)

    if data.status_code == 200:
        return_status = True
        result = data.json()
    else:
        module.fail_json(msg='Unable to retrieve serial number: - %s' % data.status_code)

    return_msg = { 'result': result, 'changed': return_status } 
    module.exit_json(**return_msg)
    
main()
