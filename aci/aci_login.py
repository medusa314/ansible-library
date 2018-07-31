#!/usr/bin/env python2.7

# Copyright (c) 2017 Sybil Melton, Dominion Enterprises
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = '''
---

module: aci_login
short_description: Log in to an ACI fabric
description:
    - Offers ability to log in to fabric
author: Sybil Melton
requirements:
    - ACI Fabric 1.3.2j +
    - Cobra SDK
options:
    host:
        description:
            - IP Address or hostname of APIC resolvable by Ansible control host
        required: true
        default: null
        choices: []
        aliases: []
    username:
        description:
            - Username used to login to the switch
        required: true
        default: null
        choices: []
        aliases: []
    password:
        description:
            - Password used to login to the switch
        required: true
        default: null
        choices: []
        aliases: []
    protocol:
        description:
            - Dictates connection protocol
        required: false
        default: https
        choices: ['http', 'https']
        aliases: []
'''
EXAMPLES = '''
aci_login: host={{ inventory_hostname }} username={{ USERNAME }} password={{ DEVICE_PASSWORD }}
'''
RETURN = '''
xmldoc:
    description:  XML of object
    returned:  success
    type: string
    sample: <?xml version=\"1.0\" encoding=\"UTF-8\"?>
changed:
    description:  Whether or not changed
    returned: True
    type: string
    sample: True
'''
try:
    HAS_COBRA = True
    from cobra.mit.access import MoDirectory
    from cobra.mit.session import LoginSession
    from cobra.internal.codec.xmlcodec import toXMLStr
except ImportError as ie:
    HAS_COBRA = False

import urllib3
import logging
from ansible.module_utils.basic import *

def print_query_xml(xml_file, pretty_print=True):
    print toXMLStr(xml_file, prettyPrint=pretty_print)
    return toXMLStr(xml_file, prettyPrint=pretty_print)

def apic_login(host, user, password):
    """Login to APIC"""
    if not host.startswith(('http', 'https')):
        host = 'https://' + host
    lsess = LoginSession(host, user, password)
    moDir = MoDirectory(lsess)
    moDir.login()
    moDir = moDir
    return moDir

urllib3.disable_warnings()
logging.captureWarnings(True)

def main():

    module = AnsibleModule(
        argument_spec=dict(
            host=dict(required=True),
            username=dict(type='str', default='admin'),
            password=dict(type='str', default='C1sco12345'),
            protocol=dict(choices=['http', 'https'], default='https')
        ),
        supports_check_mode=True
    )
    if not HAS_COBRA:
        module.fail_json(msg='Ensure you have the ACI Cobra SDK installed',
                         error=str(ie))

    username = module.params['username']
    password = module.params['password']
    host = module.params['host']
    
    moDir = apic_login(host, username, password)
    uniMo = moDir.lookupByDn('uni')
    
    changed = False
    results = {}
    xmldoc = ''
    
    xmldoc = print_query_xml(uniMo)
    if module.check_mode:
        module.exit_json(changed=True, xmldoc=xmldoc)
    else:
        changed = True

    results['xmldoc'] = xmldoc
    results['changed'] = changed

    module.exit_json(**results)

main()