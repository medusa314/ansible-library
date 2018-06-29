#!/usr/bin/env python2.7

# Copyright (c) 2017 Sybil Melton, Dominion Enterprises
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = '''
---
module: aci_interface
short_description: Configure fabric interfaces
description:
    - Provides ability to configure interface access policies
author: Sybil Melton
requirements:
    - ACI Fabric 2.1.2e +
    - Cobra SDK
options:
    switch_profile:
        description:
            - Name of the switch profile the interface belongs to, named per switch or pair of switches.
        required: true
        default: null
        choices:[]
        aliases: []
    interface_name:
        description:
            - Port Block name
        required: false
        default: null
        choices: []
        aliases: []
    interface_type:
        description:
            - Whether port is individual or port of a port-channel
        required: true
        default: individual
        choices: [individual, pc, vpc]
        aliases: []
    interface_policy_group:
        description:
            - Policy group defines the interface policies applied.  i.e. speed, duplex, CDP, LACP
        required: true
        default: null
        choices: []
        aliases: []
    interface_port:
        description:
            - port to be configured with same configuration
        required: true
        default: null
        choices: []
        aliases: []
    interface_description:
        description:
            - Port description
        required: false
        default: null
        choices: []
        aliases: []
    interface_overwrite:
        description:
            - Whether or not to overwrite the configuration on a port
        required: false
        default: null
        choices: [True, False]
        aliases: []
    state:
        description:
            - Desired state of the interface
        required: false
        default: present
        choices: ['present','absent']
        aliases: []
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
# name: Configure leaf individual port
aci_interface:
    switch_profile: DS-ACI-93128-02A
    interface_type: individual
    interface_policy_group: ANSIBLE_1G
    interface_port: 1/26
    state: present
    interface_name: ANSIBLE_TEST
    interface_description: "Test NIC 1"
    host: "{{ inventory_hostname }}"
    username: "{{ USERNAME }}"
    password: "{{ DEVICE_PASSWORD }}"
      
# name: Configure leaf interface for virtual port-channel
aci_interface:
    switch_profile: DS-ACI-9396-01A
    interface_type: vpc
    interface_policy_group: DS-UCS-6140-1B-VPC
    interface_port: 1/31
    state: present
    interface_name: DS-UCS-6140-1B_31
    host: "{{ inventory_hostname }}"
    username: "{{ USERNAME }}"
    password: "{{ DEVICE_PASSWORD }}"

# name: Delete configured interface
aci_interface:
    switch_profile: DS-ACI-93128-02A
    interface_name: ANSIBLE_TEST
    state: absent
'''
RETURN = '''
xmldoc:
    description:  XML of object
    returned:  success
    type: string
    sample: <infraAccPortP name="DS-ACI-93128-02A_ifselector" status="created,modified">
              <infraHPortS name="ANSIBLE_TEST" status="created,modified" type="range">
                <infraRsAccBaseGrp status="created,modified" tDn="uni/infra/funcprof/accportgrp-ANSIBLE_1G"/>
                <infraPortBlk descr="Test NIC 1" fromCard="1" fromPort="26" name="block1" status="created,modified" toPort="26"/>
              </infraHPortS>
            </infraAccPortP>
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
    from cobra.mit.request import ConfigRequest
    from cobra.mit.request import DnQuery
    from cobra.internal.codec.xmlcodec import toXMLStr
    from cobra.model.infra import AccPortP, HPortS, PortBlk, RsAccBaseGrp, NodeBlk, RsAccPortP, AccPortGrp, AccBndlGrp
except ImportError as ie:
    HAS_COBRA = False

import urllib3
import logging

# commits the change to the APIC
def commit_change(moDir, changed_object=None, print_xml=True, pretty_print=True):
    """
    :param moDir: login session
    :param changed_object: mo of the changed object
    :param print_xml: if set, prints XML to stdout
    :param pretty_print: if set, uses pretty print
    """
    changed_object = mo if changed_object is None else changed_object
    if print_xml:
        print_query_xml(changed_object, pretty_print=pretty_print)
    config_req = ConfigRequest()
    config_req.addMo(changed_object)
    moDir.commit(config_req)
    
# pretty print XML
def print_query_xml(xml_file, pretty_print=True):
    """
    :param xml_file: XML to be printed
    :param pretty_print: if set, uses pretty print
    :return XML to string
    """
    print toXMLStr(xml_file, prettyPrint=pretty_print)
    return toXMLStr(xml_file, prettyPrint=pretty_print)

def normalize_to_list(data):
    if isinstance(data, str) or isinstance(data, unicode):
        return [data]
    elif data:
        return data
    else:
        return []

def check_if_switchport_configured(moDir, switchProfile, range):
    '''
    :param moDir: login session
    :param switchProfile: switch Profile name 
    :param range: switch port range to check
    :return: True if configured
    '''
    configured = []
    proposed = []
    
    card, fromPort, toPort = input_ports(range)
    proposed.append(card + '/' + fromPort)
    fromP = int(fromPort)
    toP = int(toPort)
    while(fromP != toP):
        fromP +=1
        proposed.append(card + '/' + str(fromP))
    
    uri = 'uni/infra/accportprof-{0}_ifselector'
    dnq = DnQuery(uri.format(switchProfile))
    dnq.queryTarget = 'children'
    dnq.classFilter = 'infraHPortS'
    ports = moDir.query(dnq)
    names = [each.name for each in ports if each]
    for name in names:
        uri2 = 'uni/infra/accportprof-{0}_ifselector/hports-{1}-typ-range'
        dnq2 = DnQuery(uri2.format(switchProfile, name))
        dnq2.queryTarget = 'children'
        dnq2.classFilter = 'infraPortBlk'
        blocks = moDir.query(dnq2)
        for block in blocks:
            startingPort = block.fromPort
            card = block.fromCard
            configured.append(card + '/' + startingPort)
            s = int(startingPort)
            while s != int(block.toPort):
                s += 1
                configured.append(card + '/' + str(s))
    
    for p in proposed:
        if p in configured:
            return True            
    return False

def look_up_mo(moDir, path, mo_name, set_mo=True):
    temp_mo = moDir.lookupByDn(path + mo_name)
    if set_mo:
        mo = temp_mo
    return temp_mo

def check_if_mo_exist(moDir, path, mo_name='', module=None, description='', detail_description='', set_mo=True, return_false=False):
    """
    :param moDir: login session
    :param path: the path to the MO
    :param mo_name: the name of the MO
    :param module: the module of the MO
    :param description: message shown when MO does not exist
    :param detail_description: message shown when MO does not exist
    :param set_mo: if set, mo is set to be Tenant
    :param return_false: when true, the function will return false if MO does not exist
    :return: the MO if exists
    """
    temp_mo = look_up_mo(moDir, path, mo_name, set_mo=set_mo)
    if module is not None and not isinstance(temp_mo, module):
        if detail_description != '':
            print detail_description
        else:
            print description, mo_name, 'does not exist.'
        if return_false:
            return False
        else:
            print 'The programing is exiting.'
            sys.exit()
    if set_mo:
        mo = temp_mo
    return temp_mo 

def input_ports(num):
    '''
    :param moDir: login session
    :param num: port or range
    :return: card, from port and to port for a range
    '''
    card_and_port = str(num)
    card_and_port = re.split('/|-',card_and_port)
    card = card_and_port[0]
    fromPort = card_and_port[1]
    toPort = fromPort if len(card_and_port) <= 2 else card_and_port[2]
    return card, fromPort, toPort

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
            username=dict(type='str', default=''),
            password=dict(type='str', default=''),
            protocol=dict(choices=['http', 'https'], default='https'),
            state=dict(choices=['present', 'absent'], default='present'),
            switch_profile=dict(type='str',required=True),
            interface_type=dict(choices=['individual', 'pc', 'vpc'], default='individual'),
            interface_policy_group=dict(type='str', default=''),
            interface_port=dict(type='str', default=''),
            interface_name=dict(type='str', required=True),
            interface_overwrite=dict(type='bool', default=False),
            interface_description=dict(type='str', default='')
        ),
        supports_check_mode=True
    )
    if not HAS_COBRA:
        module.fail_json(msg='Ensure you have the ACI Cobra SDK installed',
                         error=str(ie))

    username = module.params['username']
    password = module.params['password']
    host = module.params['host']
    
    state = module.params['state'].lower()
    
    switch_profile = module.params['switch_profile']
    interface_type = module.params['interface_type'].lower()
    interface_policy_group = module.params['interface_policy_group']
    interface_port = module.params['interface_port']
    interface_description = module.params['interface_description']
    interface_name = module.params['interface_name']
    interface_overwrite = module.params['interface_overwrite']
    
    moDir = apic_login(host, username, password)
    infra = moDir.lookupByDn('uni/infra')
    
    infra_accportp = None
    
    #module will configure interface
    if state == 'present':
        if check_if_mo_exist(moDir,'uni/infra/accportprof-', switch_profile + '_ifselector', AccPortP, 'Interface Profile', return_false=True, set_mo=False):
            infra_accportp = AccPortP(infra, switch_profile + '_ifselector')
        else:
            module.fail_json(msg='Interface Selector Profile ' + switch_profile + ' does not exist.  Look under Fabric -> Access Policies -> Interface Policies -> Profiles -> Leaf Profiles')
        
        # default hports type is range.  interface description becomes host selector name
        infra_hports = HPortS(infra_accportp, interface_name, 'range')
            
        configured = check_if_switchport_configured(moDir, switch_profile, interface_port)
        if configured and not interface_overwrite:
            module.fail_json(msg='Interface ' + interface_port + ' on ' + switch_profile + ' is already configured.  Check profile under Fabric -> Access Policies -> Interface Policies -> Profiles -> Leaf Profiles')
        else:
            card, fromPort, toPort = input_ports(interface_port)
        
        infra_portblk = PortBlk(infra_hports, 'block0', fromCard=card, fromPort=fromPort, toPort=toPort, descr=interface_description)
        
        if interface_type == 'individual':
            policy_group_type = 'accportgrp'
            moClass = AccPortGrp
        elif interface_type in ['pc', 'vpc']:
            policy_group_type = 'accbundle'
            moClass = AccBndlGrp
        else:
            module.fail_json(msg='Invalid interface type.  Options are "individual", "pc", or "vpc"')
            
        if check_if_mo_exist(moDir,'uni/infra/funcprof/' + policy_group_type + '-', interface_policy_group, moClass, 'Interface Policy Group', return_false=True, set_mo=False):
            infra_rsaccbasegrp = RsAccBaseGrp(infra_hports, tDn='uni/infra/funcprof/' + policy_group_type + '-' + interface_policy_group)
        else:
            module.fail_json(changed=True, msg='Interface Policy Group ' + interface_policy_group + ' does not exist.  Look under Fabric -> Access Policies -> Interface Policies -> Policy Groups -> Leaf Policy Groups')
    # module will delete interface                
    elif state == "absent":
        infra_hports = check_if_mo_exist(moDir,'uni/infra/accportprof-', switch_profile + '_ifselector/hports-' + interface_name + '-typ-range', HPortS, 'Interface Selector Profile', return_false=True, set_mo=False)
        if infra_hports:
            infra_hports.delete()
        else:
            module.fail_json(msg=' interface name ' + interface_name + ' does not exist.')
    else:       
        module.fail_json(msg='Invalid interface status.  Options are "present" or "absent"')
        
    results = {}
    xmldoc = ''
    factsdict = {}
    changed = False
    
    # Build configuration and commit if not run in check-mode    
    if infra_accportp and state == 'present':
        xmldoc = print_query_xml(infra_accportp)
        factsdict['configuration'] = xmldoc
        if module.check_mode:
            module.exit_json(changed=True, ansible_facts=factsdict)
        else:
            changed = True
            commit_change(moDir, infra_accportp, print_xml=False)
    elif infra_hports and state == 'absent':
        xmldoc = print_query_xml(infra_hports)
        factsdict['configuration'] = xmldoc
        if module.check_mode:
            module.exit_json(changed=True, ansible_facts=factsdict)
        else:
            changed = True
            commit_change(moDir, infra_hports, print_xml=False)

    results['xmldoc'] = xmldoc
    results['state'] = state
    results['changed'] = changed

    module.exit_json(ansible_facts=factsdict, **results)
    

from ansible.module_utils.basic import *
main()