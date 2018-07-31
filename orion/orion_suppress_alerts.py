#!/usr/bin/env python2.7

# Copyright (c) 2017 Sybil Melton, Dominion Enterprises
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = '''
---

module: orion_suppress_alerts
short_description: Suppress Orion alerts
description:
    - Offers ability suppress alerts for managed node by ip address
author: Sybil Melton
requirements:
    - Solarwinds
    - Orion SDK
options:
    host:
        description:
            - IP Address or hostname of Orion server
        required: true
        default: null
        choices: []
        aliases: []
    username:
        description:
            - Username used to login to the server
        required: true
        default: null
        choices: []
        aliases: []
    password:
        description:
            - Password used to login to the server
        required: true
        default: null
        choices: []
        aliases: []
    ip:
        description:
            - IP address of the node to be suppressed
        required: true
        default: 127.0.0.1
        choices: []
        aliases: []
    state:
        description:
            - Desired state of the alerts
        required: false
        default: present
        choices: ['present','absent']
        aliases: []
'''
EXAMPLES = '''
orion_suppress_alerts: 
  host: {{ inventory_hostname }} 
  username: {{ USERNAME }}
  password: {{ DEVICE_PASSWORD }}
  ip: 10.1.1.20
  state: present
  
orion_suppress_alerts: 
  host: {{ inventory_hostname }} 
  username: {{ USERNAME }}
  password: {{ DEVICE_PASSWORD }}
  ip: 10.1.1.20
  state: absent
'''
RETURN = '''
changed:
    description:  Whether or not changed
    returned: True
    type: string
    sample: True
'''
try:
    HAS_ORION = True
    from orionsdk import SwisClient
except ImportError as ie:
    HAS_ORION = False

import urllib3
import logging
from datetime import datetime, timedelta
import requests

urllib3.disable_warnings()
logging.captureWarnings(True)

def main():

    module = AnsibleModule(
        argument_spec=dict(
            host=dict(required=True),
            username=dict(type='str',required=True),
            password=dict(type='str',required=True),
            ip=dict(type='str', default='127.0.0.1'),
            state=dict(choices=['present', 'absent'], default='present')
        ),
        supports_check_mode=False
    )
    if not HAS_ORION:
        module.fail_json(msg='Ensure you have the Orion SDK installed',
                         error=str(ie))

    username = module.params['username']
    password = module.params['password']
    host = module.params['host']
    ip = module.params['ip']
    state = module.params['state']
    
    results = {}
    changed = False
    
    swis = SwisClient(host, username, password)
    
    result = swis.query('SELECT Uri FROM Orion.Nodes WHERE IPAddress = @ip_addr', ip_addr=ip)
    
    if result['results']:
        uri = [result['results'][0]['Uri']]
    else:
        module.fail_json(msg='Node is not managed by Orion')
        
    if state == 'present':
        swis.invoke('Orion.AlertSuppression', 'SuppressAlerts', uri)
    else:
        swis.invoke('Orion.AlertSuppression', 'ResumeAlerts', uri)
    
    
    results['changed'] = changed
    results['state'] = state
    module.exit_json(**results)
    

from ansible.module_utils.basic import *
main()