#!/usr/bin/env python2.7

# Copyright (c) 2017 Sybil Melton, Dominion Enterprises
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = '''
---
module: aci_policy_group
short_description: Configure fabric policy groups
description:
    - Provides ability to configure fabric policy groups
author: Sybil Melton
requirements:
    - ACI Fabric 1.3.2j +
    - Cobra SDK
options:
    group_name:
        description:
            - Name of the group to be configured
        required: true
        default: null
        choices:[]
        aliases: []
    group_type:
        description:
            - Whether policy group is for individual or port-channel ports
        required: true
        default: individual
        choices: [individual, pc, vpc]
        aliases: []
    group_linklevel:
        description:
            - Link Level Policy, i.e. speed and duplex, choices correspond with what is already configured in the APIC
        required: true
        default: null
        choices: [1G, 10G, 40G, 100-AUTO, 100-FULL]
        aliases: []
    group_cdp:
        description:
            - CDP Policy, choices correspond with what is already configured in the APIC
        required: false
        default: null
        choices: [CDP-OFF, CDP-ON]
        aliases: []
    group_lldp:
        description:
            - LLDP Policy, choices correspond with what is already configured in the APIC
        required: false
        default: null
        choices: [LLDP-OFF, LLDP-ON, LLDP-RECEIVE, LLDP-TRANSMIT]
        aliases: []
    group_stp:
        description:
            - STP BPDUGUARD Policy, choices correspond with what is already configured in the APIC
        required: false
        default: null
        choices: [BPDUGUARD-ON, BPDUFILTER-ON]
        aliases: []
    group_pc:
        description:
            - Port Channel Policy, choices correspond with what is already configured in the APIC
        required: false
        default: null
        choices: [LACP-OFF, ACTIVE, PASSIVE, MAC-PIN]
        aliases: []
    group_monitoring:
        description:
            - Monitoring Policy
        required: false
        default: default
        choices: []
        aliases: []
    group_overwrite:
        description:
            - True if wish to overwrite existing Policy Group
        required: false
        default: False
        choices: [True, False]
        aliases: []
    group_aep:
        description:
            - Attached Entity Profile, choices configured in Fabric -> Access Policies -> Global Policies -> Attachable Access Entity Profiles
        required: true
        default: null
        choices: []
        aliases: []
    state:
        description:
            - Desired state of the policy group
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

- name: Configure Policy Group for individual ports
  aci_policy_group:
      group_name: LEGACY_1G
      group_type: individual
      group_linklevel: 1G
      group_cdp: CDP-OFF
      group_lldp: LLDP-OFF
      group_stp: BPDUGUARD-ON
      group_aep: LEGACY
      state: present
      host: "{{ inventory_hostname }}"
      username: "{{ USERNAME }}"
      password: "{{ DEVICE_PASSWORD }}"
      
- name: Configure leaf interface for virtual port-channel
  aci_policy_group:
      group_name: DS-ESX-Z01-SIO01-VPC
      group_type: vpc
      group_linklevel: 10G
      group_cdp: CDP-ON
      group_lldp: LLDP-ON
      group_stp: BPDUGUARD-ON
      group_pc: ACTIVE
      group_aep: DS-AVS-01
      host: "{{ inventory_hostname }}"
      username: "{{ USERNAME }}"
      password: "{{ DEVICE_PASSWORD }}"

- name: Configure leaf interface for virtual port-channel
  aci_policy_group:
      group_name: BOATS-HPBLADECHASSIS-A-PC
      group_type: pc
      group_linklevel: 1G
      group_cdp: CDP-OFF
      group_lldp: LLDP-OFF
      group_stp: BPDUGUARD-ON
      group_pc: LACP-OFF
      group_aep: LEGACY
      host: "{{ inventory_hostname }}"
      username: "{{ USERNAME }}"
      password: "{{ DEVICE_PASSWORD }}"
      
- name: Delete configured interface
  aci_policy_group:
    group_name: BOATS-HPBLADECHASSIS-A-PC
    group_type: pc
    state: absent
'''
try:
    HAS_COBRA = True
    from cobra.mit.access import MoDirectory
    from cobra.mit.session import LoginSession
    from cobra.mit.request import ConfigRequest
    from cobra.mit.request import DnQuery
    from cobra.model.fv import Tenant
    from cobra.internal.codec.xmlcodec import toXMLStr
    from cobra.model.infra import AttEntityP, AccPortGrp, AccBndlGrp, RsAttEntP, RsHIfPol, RsCdpIfPol, RsLldpIfPol, RsStpIfPol, RsLacpPol, RsMonIfInfraPol,  AccBndlSubgrp, RsLacpIfPol
    from cobra.model.fabric import HIfPol
    from cobra.model.cdp import IfPol as cdpIfPol
    from cobra.model.lldp import IfPol as lldpIfPol
    from cobra.model.lacp import LagPol
    from cobra.model.stp import IfPol as stpIfPol
    from cobra.model.mon import InfraPol
except ImportError as ie:
    HAS_COBRA = False

import urllib3
import logging

def get_ports_in_group(moDir, uri):
    '''
    :param moDir: login session
    :param uri: dn of the policy group
    :return: list of ports configured for a policy group
    '''
    ports = []
    dnq = DnQuery(uri)
    dnq.queryTarget = 'children'
    dnq.classFilter = 'infraRtAccBaseGrp'
    ports = moDir.query(dnq)
    return ports

def apic_login(host, user, password):
    """Login to APIC"""
    if not host.startswith(('http', 'https')):
        host = 'https://' + host
    lsess = LoginSession(host, user, password)
    moDir = MoDirectory(lsess)
    moDir.login()
    moDir = moDir
    return moDir

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
# disable warnings for uncheck certificate
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
            group_name=dict(type='str',required=True),
            group_type=dict(choices=['individual', 'pc', 'vpc'], default='individual'),
            group_linklevel=dict(type='str', default=''),
            group_cdp=dict(type='str', default=''),
            group_lldp=dict(type='str', default=''),
            group_stp=dict(type='str', default=''),
            group_pc=dict(type='str', default=''),
            group_aep=dict(type='str', default=''),
            group_overwrite=dict(type='bool', default=False),
            group_monitoring=dict(type='str', default='default')
        ),
        supports_check_mode=True
    )
    if not HAS_COBRA:
        module.fail_json(msg='Ensure you have the ACI Cobra SDK installed',
                         error=str(ie))
    
    # local variables from module parameters
    username = module.params['username']
    password = module.params['password']
    host = module.params['host']
    
    state = module.params['state'].lower()

    group_name = module.params['group_name']
    group_type = module.params['group_type'].lower()
    group_linklevel = module.params['group_linklevel']
    group_cdp = module.params['group_cdp']
    group_lldp = module.params['group_lldp']
    group_stp = module.params['group_stp']
    group_pc = module.params['group_pc']
    group_aep = module.params['group_aep']
    group_monitoring = module.params['group_monitoring']
    group_overwrite = module.params['group_overwrite']
    
    # log into the fabric
    moDir = apic_login(host, username, password)
    groupMo = moDir.lookupByDn('uni/infra/funcprof/')
    
    infra_acc = None
    
    if state == 'present':
        # create port group based on type
        if group_type != 'individual':
            moClass = AccBndlGrp
            if not check_if_mo_exist(moDir,'uni/infra/funcprof/accbundle-', group_name, moClass, 'Interface Policy Group', return_false=True, set_mo=False) or group_overwrite:
                if group_type == 'vpc':
                    infra_acc = AccBndlGrp(groupMo, group_name, lagT='node')
                    infra_rsmonifinfrapol = RsLacpPol(infra_acc, tnLacpLagPolName=group_pc)
                else:
                    infra_acc = AccBndlGrp(groupMo, group_name)
                    infra_rsmonifinfrapol = RsLacpPol(infra_acc, tnLacpLagPolName=group_pc)
            else:
                module.fail_json(changed=True, msg='Interface Policy Group ' + group_name + ' exists.  Look under Fabric -> Access Policies -> Interface Policies -> Policy Groups')
        else:
            moClass = AccPortGrp
            if not check_if_mo_exist(moDir,'uni/infra/funcprof/accportgrp-', group_name, moClass, 'Interface Policy Group', return_false=True, set_mo=False) or group_overwrite:
                infra_acc = AccPortGrp(groupMo, group_name)
            else:
                module.fail_json(changed=True, msg='Interface Policy Group ' + group_name + ' exists.  Look under Fabric -> Access Policies -> Interface Policies -> Policy Groups')
        
        # Verify and assign the Link level policy
        if group_linklevel:
            if check_if_mo_exist(moDir,'uni/infra/hintfpol-', group_linklevel, HIfPol, 'Link Level Policy', return_false=True, set_mo=False):
                infra_rshifpol = RsHIfPol(infra_acc, tnFabricHIfPolName=group_linklevel)
            else:
                module.fail_json(msg=' Link Level Policy ' + group_linklevel + ' does not exist. Check Fabric -> Access Policies -> Interface Policies -> Policies -> Link Level')
        # verify and assign cdp policy
        if group_cdp:
            if check_if_mo_exist(moDir,'uni/infra/cdpIfP-', group_cdp, cdpIfPol, 'CDP Policy', return_false=True, set_mo=False):
                infra_rscdpifpol = RsCdpIfPol(infra_acc, tnCdpIfPolName=group_cdp)
            else:
                module.fail_json(msg=' CDP Policy ' + group_cdp + ' does not exist. Check Fabric -> Access Policies -> Interface Policies -> Policies -> CDP Interface')
        # verify and assign lldp policy
        if group_lldp:
            if check_if_mo_exist(moDir,'uni/infra/lldpIfP-', group_lldp, lldpIfPol, 'LLDP Policy', return_false=True, set_mo=False):
                infra_rslldpifpol = RsLldpIfPol(infra_acc, tnLldpIfPolName=group_lldp)
            else:
                module.fail_json(msg=' LLDP Policy ' + group_lldp + ' does not exist. Check Fabric -> Access Policies -> Interface Policies -> Policies -> LLDP Interface')
        # verify and assign stp policy
        if group_stp:
            if check_if_mo_exist(moDir,'uni/infra/ifPol-', group_stp, stpIfPol, 'BPDU Policy', return_false=True, set_mo=False):
                infra_rsstpifpol = RsStpIfPol(infra_acc, tnStpIfPolName=group_stp)
            else:
                module.fail_json(msg=' STP Policy ' + group_lldp + ' does not exist. Check Fabric -> Access Policies -> Interface Policies -> Policies -> Spanning Tree Interface')
        # verify and assign monitoring policy
        if group_monitoring:
            if check_if_mo_exist(moDir,'uni/infra/moninfra-', group_monitoring, InfraPol, 'Monitoring Policy', return_false=True, set_mo=False):
                infra_rsmonifinfrapol = RsMonIfInfraPol(infra_acc, tnMonInfraPolName=group_monitoring)
            else:
                module.fail_json(msg=' Monitoring Policy ' + group_monitoring + ' does not exist. Check Fabric -> Access Policies -> Monitoring Policies')
        # verify and assign AEP
        if group_aep:
            if check_if_mo_exist(moDir,'uni/infra/attentp-', group_aep, AttEntityP, 'Attached Entity Profile', return_false=True, set_mo=False):
                infra_rsattentp = RsAttEntP(infra_acc, tDn='uni/infra/attentp-'+ group_aep)
            else:
                module.fail_json(msg=' Attached Entity Profile ' + group_aep + ' does not exist. Check Fabric -> Access Policies -> Global Policies -> Attachable Access Entity Profiles')
            
    elif state == "absent":
        if group_type == 'individual':
            uri = 'uni/infra/funcprof/accportgrp-' + group_name
            infra_acc = check_if_mo_exist(moDir,'uni/infra/funcprof/accportgrp-', group_name, AccPortGrp, 'Policy Group', return_false=True, set_mo=False)
        else:
            uri = 'uni/infra/funcprof/accbundle-' + group_name
            infra_acc = check_if_mo_exist(moDir,'uni/infra/funcprof/accbundle-', group_name, AccBndlGrp, 'Policy Group', return_false=True, set_mo=False)
        if infra_acc:
            ports = get_ports_in_group(moDir, uri)
            if len(ports) == 0:
                infra_acc.delete()
            else:
                module.fail_json(msg=' group name ' + group_name + ' as ' + group_type + ' has ports configured in it.')
        else:
            module.fail_json(msg=' group name ' + group_name + ' as ' + group_type + ' does not exist.')
    else:       
        module.fail_json(msg='Invalid group status.  Options are "present" or "absent"')
        
    results = {}
    xmldoc = ''
    changed = False
    factsdict = {}
    
    if infra_acc and state == 'present':
        xmldoc = print_query_xml(infra_acc)
        factsdict['configuration'] = xmldoc
        if module.check_mode:
            module.exit_json(changed=True, ansible_facts=factsdict)
        else:
            changed = True
            commit_change(moDir, infra_acc, print_xml=False)
    elif infra_acc and state == 'absent':
        xmldoc = print_query_xml(infra_acc)
        factsdict['configuration'] = xmldoc
        if module.check_mode:
            module.exit_json(changed=True, ansible_facts=factsdict)
        else:
            changed = True
            commit_change(moDir, infra_acc, print_xml=False)

    results['xmldoc'] = xmldoc
    results['state'] = state
    results['changed'] = changed

    module.exit_json(ansible_facts=factsdict,**results)
    

from ansible.module_utils.basic import *
main()