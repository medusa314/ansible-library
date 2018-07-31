#!/usr/bin/env python2.7

# Copyright (c) 2017 Sybil Melton, Dominion Enterprises
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = '''
---
module: aci_epg_static_port
short_description: Configure static ports in EPG
description:
    - Provides ability to add static ports into an End Point Group.  Verifies that the AEP for the policy group and the physical domain match.  Verifies the vlan is in vlan pool for configured domain
author: Sybil Melton
requirements:
    - ACI Fabric 2.1.2e +
    - Cobra SDK
options:
    leaf_profile:
        description:
            - Name of the leaf_profile the interface belongs to.
        required: true
        default: null
        choices:[]
        aliases: []
    tenant:
        description:
            - Name of the tenant.
        required: true
        default: null
        choices:[]
        aliases: []
    path_ap:
        description:
            - Name of the application Profile.
        required: true
        default: null
        choices:[]
        aliases: []
    path_epg:
        description:
            - Name of the End Point Group.
        required: true
        default: null
        choices:[]
        aliases: []
    path_type:
        description:
            - Whether port is individual or port of a port-channel
        required: true
        default: individual
        choices: [individual, pc, vpc]
        aliases: []
    path_port:
        description:
            - Physical ports that will be added to the EPG
        required: false
        default: null
        choices: []
        aliases: []
    path_name:
        description:
            - Physical ports that will be added to the EPG
        required: false
        default: null
        choices: []
        aliases: []
    path_description:
        description:
            - port description
        required: false
        default: null
        choices: []
        aliases: []
    path_encap:
        description:
            - port encapsulation, vlan- number
        required: false
        default: null
        choices: []
        aliases: []
    path_mode
        description:
            - port encapsulation, vlan- number
        required: false
        default: 'native'
        choices: ['untagged', 'regular', 'native']
        aliases: []
    path_fex
        description:
            - FEX number
        required: false
        default: null
        choices: []
        aliases: []
    path_immediancy:
        description:
            - Deployment immediancy
        required: false
        default: 'lazy'
        choices: ['immediate', 'lazy']
        aliases: []
    state:
        description:
            - Desired state of the path
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
            - Username used to login
        required: true
        default: null
        choices: []
        aliases: []
    password:
        description:
            - Password used to login
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
# name: Configure individual port as epg static port
aci_epg_static_port:
    leaf_profile: DS-ACI-93128-02A
    tenant: SANDBOX
    path_type: individual
    path_port: 1/26
    path_description: ANSIBLE_TEST
    path_ap: ANSIBLE
    path_epg: ansible_inside
    path_encap: vlan-2
    path_mode: native
    path_immediancy: lazy
    state: present
    host: "{{ inventory_hostname }}"
    username: "{{ USERNAME }}"
    password: "{{ DEVICE_PASSWORD }}"
      
# name: Configure port-channel as epg static port
aci_epg_static_port:
    leaf_profile: DS-ACI-93128-02A
    tenant: SANDBOX
    path_type: pc
    path_name: ANSIBLE-PC
    path_description: ANSIBLE_TEST2
    path_ap: ANSIBLE
    path_epg: ansible_dmz
    path_encap: vlan-3
    path_mode: regular
    path_immediancy: lazy
    state: present
    host: "{{ inventory_hostname }}"
    username: "{{ USERNAME }}"
    password: "{{ DEVICE_PASSWORD }}"

# name: Configure fex port as epg static port
aci_epg_static_port:
    leaf_profile: FEX105-R05E01
    tenant: SANDBOX
    path_type: individual
    path_port: 1/26
    path_description: ANSIBLE_FEX_TEST
    path_ap: ANSIBLE
    path_epg: ansible_inside
    path_encap: vlan-2
    path_mode: native
    path_immediancy: lazy
    path_fex: 105
    state: present
    host: "{{ inventory_hostname }}"
    username: "{{ USERNAME }}"
    password: "{{ DEVICE_PASSWORD }}"

# name: Delete configured interface
aci_epg_static_port:
    leaf_profile: FEX105-R05E01
    tenant: SANDBOX
    path_type: individual
    path_port: 1/26
    path_ap: ANSIBLE
    path_epg: ansible_inside
    path_fex: 105
    state: absent
    host: "{{ inventory_hostname }}"
    username: "{{ USERNAME }}"
    password: "{{ DEVICE_PASSWORD }}"
'''
RETURN = '''
xmldoc:
    description:  XML of object
    returned:  success
    type: string
    sample: 
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
    from cobra.model.fv import RsPathAtt, AEPg, Ap, Tenant
    from cobra.model.infra import FexP, AccPortP
except ImportError as ie:
    HAS_COBRA = False

import urllib3
import logging

def get_fexport_policy_group(moDir, fexProfile, port_name):
    '''
    :param moDir: login session
    :param fexProfile: profile name of the FEX
    :param port_name: name of the port
    :return: policy group for the configured port. '0' if not configured
    '''
    uri = 'uni/infra/fexprof-{0}/hports-{1}-typ-range'
    dnq = DnQuery(uri.format(fexProfile, port_name))
    dnq.queryTarget = 'children'
    dnq.classFilter = 'infraRsAccBaseGrp'
    rsAccBaseGrp = moDir.query(dnq)
    try:
        if rsAccBaseGrp[0].tCl == 'infraAccBndlGrp':
            policy_group = str(rsAccBaseGrp[0].tDn).split('accbundle-')[1]
        elif rsAccBaseGrp[0].tCl == 'infraAccPortGrp':
            policy_group = str(rsAccBaseGrp[0].tDn).split('accportgrp-')[1]
    except IndexError:
        policy_group = '0'
    return policy_group

def get_switchport_policy_group(moDir, leafProfile, port_name):
    '''
    :param moDir: login session
    :param leafProfile: profile name of the leaf
    :param port_name: name of the port
    :return: policy group for the configured port. '0' if not configured
    '''
    uri = 'uni/infra/accportprof-{0}_ifselector/hports-{1}-typ-range'
    dnq = DnQuery(uri.format(leafProfile, port_name))
    dnq.queryTarget = 'children'
    dnq.classFilter = 'infraRsAccBaseGrp'
    rsAccBaseGrp = moDir.query(dnq)
    try:
        if rsAccBaseGrp[0].tCl == 'infraAccBndlGrp':
            policy_group = str(rsAccBaseGrp[0].tDn).split('accbundle-')[1]
        elif rsAccBaseGrp[0].tCl == 'infraAccPortGrp':
            policy_group = str(rsAccBaseGrp[0].tDn).split('accportgrp-')[1]
        else:
            policy_group = '0'
    except IndexError:
        policy_group = '0'
    return policy_group

def get_switchports(moDir, leafProfile):
    '''
    :param moDir: login session
    :param leafProfile: leaf Profile name 
    :return: list of all configured ports
    '''
    configured = []
    uri = 'uni/infra/accportprof-{0}_ifselector'
    dnq = DnQuery(uri.format(leafProfile))
    dnq.queryTarget = 'children'
    dnq.classFilter = 'infraHPortS'
    ports = moDir.query(dnq)
    names = [each.name for each in ports if each]
    for name in names:
        uri2 = 'uni/infra/accportprof-{0}_ifselector/hports-{1}-typ-range'
        dnq2 = DnQuery(uri2.format(leafProfile, name))
        dnq2.queryTarget = 'children'
        dnq2.classFilter = 'infraPortBlk'
        blocks = moDir.query(dnq2)
        for block in blocks:
            ints = []
            startingPort = block.fromPort
            card = block.fromCard
            ints.append(card + '/' + startingPort)
            s = int(startingPort)
            while s != int(block.toPort):
                s += 1
                ints.append(card + '/' + str(s))    
            configured.append({'name': name, 'ports':ints})            
    return configured

def get_switchport_name(moDir, switchProfile, port):
    '''
    :param moDir: login session
    :param switchProfile: switch Profile name 
    :param port: switch port to check
    :return: name of the configured port. '' if not configured
    '''
    configured = get_switchports(moDir, switchProfile)
    for config in configured:
        if port in config['ports']:
            return config['name']
    return ''

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

def check_if_fexport_configured(moDir, fexProfile, range):
    '''
    :param moDir: login session
    :param fexProfile: FEX Profile name 
    :param range: FEX port range to check
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
    
    uri = 'uni/infra/fexprof-{0}'
    dnq = DnQuery(uri.format(fexProfile))
    dnq.queryTarget = 'children'
    dnq.classFilter = 'infraHPortS'
    ports = moDir.query(dnq)
    names = [each.name for each in ports if each]
    for name in names:
        uri2 = 'uni/infra/fexprof-{0}/hports-{1}-typ-range'
        dnq2 = DnQuery(uri2.format(fexProfile, name))
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

def get_fexports(moDir, fexProfile):
    '''
    :param moDir: login session
    :param fexProfile: FEX Profile name 
    :return: list of all configured ports
    '''
    configured = []
    uri = 'uni/infra/fexprof-{0}'
    dnq = DnQuery(uri.format(fexProfile))
    dnq.queryTarget = 'children'
    dnq.classFilter = 'infraHPortS'
    ports = moDir.query(dnq)
    names = [each.name for each in ports if each]
    for name in names:
        uri2 = 'uni/infra/fexprof-{0}/hports-{1}-typ-range'
        dnq2 = DnQuery(uri2.format(fexProfile, name))
        dnq2.queryTarget = 'children'
        dnq2.classFilter = 'infraPortBlk'
        blocks = moDir.query(dnq2)
        for block in blocks:
            ints = []
            startingPort = block.fromPort
            card = block.fromCard
            ints.append(card + '/' + startingPort)
            s = int(startingPort)
            while s != int(block.toPort):
                s += 1
                ints.append(card + '/' + str(s))
            configured.append({'name': name, 'ports':ints})
    return configured

def get_fex_port_name(moDir, fexProfile, port):
    '''
    :param moDir: login session
    :param fexProfile: FEX Profile name 
    :param range: FEX port range to check
    :return: port name if configured
    '''
    configured = get_fexports(moDir, fexProfile)
    for config in configured:
        if port in config['ports']:
            return config['name']
    return ''

def check_if_tenant_exist(moDir, tenant, return_boolean=False, set_mo=True):
    """
    :param moDir: login session
    :param return_boolean: if set, return value is True or False
    :param set_mo: if set, self.mo is set to be Tenant
    :return: the tenant MO
    """
    fv_tenant = look_up_mo(moDir, 'uni/tn-', tenant, set_mo=set_mo)
    if not isinstance(fv_tenant, Tenant):
        print 'Tenant', tenant, 'does not exist.'
        return False if return_boolean else sys.exit()
    return fv_tenant

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

# get vpc protection group to node ids
def get_vpcnodeid(moDir, leafProfile):
    """
    :param moDir: login session
    :param leafProfile: leaf Profile name 
    :return node ids for a vpc protection group.  '0' if not configured
    """
    uri = 'uni/infra/nprof-{0}'
    dnq = DnQuery(uri.format(leafProfile))
    dnq.queryTarget = 'children'
    dnq.classFilter = 'infraLeafS'
    
    leafs = moDir.query(dnq)
    dnq2 = DnQuery(leafs[0].dn)
    dnq2.queryTarget = 'children'
    nodeBlk = moDir.query(dnq2)
    dnq2.classFilter = 'infraNodeBlk'
    nodeBlk = moDir.query(dnq2)
    
    if len(nodeBlk) == 2:
        if int(nodeBlk[0].from_) < int(nodeBlk[1].from_):
            nodes = nodeBlk[0].from_ + '-' + nodeBlk[1].from_
        else:
            nodes = nodeBlk[1].from_ + '-' + nodeBlk[0].from_
    elif nodeBlk[0].from_ != nodeBlk[0].to_:
        nodes = nodeBlk[0].from_ + '-' + nodeBlk[0].to_
    else:
        return '0'
    
    # verify leafProfile has associated protection profile
    uri2 = 'uni/fabric/protpol/expgep-{0}'
    vpcs = moDir.lookupByClass('fabric.ExplicitGEp')
    vpcnodes = []
    for vpc in vpcs:
        dnq2 = DnQuery(uri2.format(vpc.name))
        dnq2.queryTarget = 'children'
        dnq2.classFilter = 'fabricNodePEp'
        nodePEp = moDir.query(dnq2)
        ids = [each.id for each in nodePEp if each]
        
        if len(ids) == 2:
            if int(ids[0]) < int(ids[1]):
                vpcnodes.append(ids[0] + '-' + ids[1])
            else:
                vpcnodes.append(ids[1] + '-' + ids[0])
        
    for vpcnode in vpcnodes:
        if nodes == vpcnode:
            return nodes
    return '0'

def get_nodeid(moDir, leafProfile):
    """
    :param moDir: login session
    :param leafProfile: leaf Profile name 
    :return node ids a switch. assumes one LeafS in leaf Profile, maximum of 2 nodes in a block. '0' if not configured
    """
    uri = 'uni/infra/nprof-{0}'
    dnq = DnQuery(uri.format(leafProfile))
    dnq.queryTarget = 'children'
    dnq.classFilter = 'infraLeafS'
    leafs = moDir.query(dnq)
    
    dnq2 = DnQuery(leafs[0].dn)
    dnq2.queryTarget = 'children'
    nodeBlk = moDir.query(dnq2)
    dnq2.classFilter = 'infraNodeBlk'
    nodeBlk = moDir.query(dnq2)
    
    if len(nodeBlk) == 2:
        if int(nodeBlk[0].from_) < int(nodeBlk[1].from_):
            return nodeBlk[0].from_ + '-' + nodeBlk[1].from_
        else:
            return nodeBlk[1].from_ + '-' + nodeBlk[0].from_
    elif len(nodeBlk) == 1:
        return nodeBlk[0].from_   
    else:
        return "0"

def get_epg_dom(moDir, uri, Aepg):
    """
    :param moDir: login session
    :param uri: dn of EPG
    :param Aepg: name of EPG 
    :return list of domains for an EPG
    """
    domains = []
    dnq = DnQuery(uri+Aepg)
    dnq.queryTarget = 'children'
    dnq.classFilter = 'fvRsDomAtt'
    rsDomAtt = moDir.query(dnq)
    # "uni/phys-LEGACY", "uni/vmmp-VMware/dom-AVS-01"
    domains = [each.tDn for each in rsDomAtt if each]
    return domains

def get_vlan_pool(moDir, domain_dn):
    '''
    :param moDir: login session
    :param domain_dn: dn of the domain
    :return: dn of a vlan pool
    '''
    dnq = DnQuery(domain_dn)
    dnq.queryTarget = 'children'
    dnq.classFilter = 'infraRsVlanNs'
    vlanNs = moDir.query(dnq)
    #there will only be one pool in the domain
    pool = vlanNs[0].tDn
    return pool
    
def get_vlans(moDir, pool_dn):
    '''
    :param moDir: login session
    :param pool_dn: dn of a vlan pool
    :return: list of vlans
    '''
    vlans = []
    dnq = DnQuery(pool_dn)
    dnq.queryTarget = 'children'
    dnq.classFilter = 'fvnsEncapBlk'
    encapBlk = moDir.query(dnq)
    for ranges in encapBlk:
        # cannot access from keyword, so access as dictionary
        startingVlan = ranges.__dict__['from'].split('-')[1]
        vlans.append('vlan-' + startingVlan)
        s = int(startingVlan)
        while s != int(ranges.to.split('-')[1]):
            s += 1
            vlans.append('vlan-' + str(s))
    return vlans

def check_static_vlan_in_domain(moDir, domain_dn, encap):
    """
    :param moDir: login session
    :param domain_dn: dn of domain
    :param encap: static vlan
    :return True if static vlan is valid for a domain
    """
    vlanPool = get_vlan_pool(moDir, domain_dn)
    pool = get_vlans(moDir, vlanPool)
    if encap in pool:
        return True
    else:
        return False

def get_domain_aep(moDir, Aep):
    '''
    :param moDir: login session
    :param Aep: attachable entity profile name
    :return: list of domains in the AEP
    '''
    uri = 'uni/infra/attentp-{0}/dompcont'
    dnq = DnQuery(uri.format(Aep))
    dnq.queryTarget = 'children'
    dnq.classFilter = 'infraAssocDomP'
    assocDomP = moDir.query(dnq)
    dompDns = [each.dompDn for each in assocDomP if each]
    return dompDns
   
def check_policy_group_in_domain(moDir, domain_dn, Aep):
    """
    :param moDir: login session
    :param domain_dn: dn of domain
    :param Aep: attachable entity profile name
    :return True if a domain is valid for the AEP 
    """
    dom_aep = get_domain_aep(moDir, Aep)
    if domain_dn in dom_aep:
        return True
    else:
        return False

def get_policy_group_aep(moDir, policyGroup, type):
    """
    :param moDir: login session
    :param policyGroup: name of policy group
    :param type: type of policy.  accbundle or accportgrp
    :return AEP for a policy group 
    """
    uri = 'uni/infra/funcprof/{0}{1}'
    dnq = DnQuery(uri.format(type, policyGroup))
    dnq.queryTarget = 'children'
    dnq.classFilter = 'infraRsAttEntP'
    rsAttEntP = moDir.query(dnq)
    try:
        aep = str(rsAttEntP[0].tDn).split('attentp-')[1]
    except IndexError:
        aep = '0'
    return aep

def check_if_port_in_epg(moDir, pathDn, mode, encap):
    """
    :param moDir: login session
    :param pathDn: dn of the static port
    :param mode: regular, untagged, or native
    :param encap: vlan id
    :return True if a port is already configured in an EPG with same configuration
    """
    proposed = pathDn.split('rspathAtt-')
    rsPathAtt = moDir.lookupByClass('fv.RsPathAtt')
    for pathAtt in rsPathAtt:
        configured = str(pathAtt.dn).split('rspathAtt-')
        if proposed == configured:
            if pathAtt.mode == 'regular' and mode == 'regular' and pathAtt.encap != encap:
                return False
            elif pathAtt.mode == mode:
                return True
    return False

# get configured port-channels
def get_bundles(moDir):
    """
    :param moDir: login session
    :return list of all the port-channels configured
    """
    bundles = []
    paths = moDir.lookupByClass('infra.AccBndlGrp')
    for path in paths:
        bundles.append(path.name)
    return bundles

def check_if_bundle_configured(moDir, name):
    """
    :param moDir: login session
    :param name: port name
    :return True if a port is configured on a switch
    """
    configured = get_bundles(moDir)
    if name in configured:
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
            leaf_profile=dict(type='str',required=True),
            tenant=dict(type='str',required=True),
            path_type=dict(choices=['individual', 'pc', 'vpc'], default='individual'),
            path_port=dict(type='str', default=''),
            path_name=dict(type='str', default=''),
            path_description=dict(type='str', default=''),
            path_ap=dict(type='str',required=True),
            path_epg=dict(type='str',required=True),
            path_encap=dict(type='str', default=''),
            path_mode=dict(choices=['regular', 'untagged', 'native'], default='native'),
            path_fex=dict(type='str', default=''),
            path_immediancy=dict(choices=['immediate', 'lazy'], default='lazy')
        ),
        supports_check_mode=True
    )
    if not HAS_COBRA:
        module.fail_json(msg='Ensure you have the ACI Cobra SDK installed',
                         error=str(ie))

    username = module.params['username']
    password = module.params['password']
    host = module.params['host']
    path_type = module.params['path_type'].lower()
    
    state = module.params['state'].lower()
    
    leaf_profile = module.params['leaf_profile']
    tenant = module.params['tenant']
    path_type = module.params['path_type']
    path_port = module.params['path_port']
    path_name = module.params['path_name']
    path_description = module.params['path_description']
    path_ap = module.params['path_ap']
    path_epg = module.params['path_epg']
    path_encap = module.params['path_encap']
    path_mode = module.params['path_mode']
    path_fex = module.params['path_fex']
    path_immediancy = module.params['path_immediancy']
    
    moDir = apic_login(host, username, password)
    
    fv_aepg = None
    fv_rsnodeatt = None
    port_name = ''
    policy_group = ''
    aep = ''
    # Verify tenant is valid
    if check_if_tenant_exist(moDir, tenant, return_boolean=True, set_mo=False):
        fv_tenant = check_if_tenant_exist(moDir, tenant, return_boolean=False, set_mo=False)
    else:
        module.fail_json(msg= tenant + ' does not exist. Check Tenants.')
    # Verify Application Profile is valid
    if check_if_mo_exist(moDir,'uni/tn-' + fv_tenant.name + '/ap-', path_ap, Ap, 'Application Profile', return_false=True, set_mo=False):
        fv_ap = check_if_mo_exist(moDir, 'uni/tn-' + fv_tenant.name + '/ap-', path_ap, Ap, return_false=False, set_mo=False)
    else:
        module.fail_json(msg= path_ap + ' application profile does not exist. Check Tenants -> Tenant ' + fv_tenant.name + ' -> Application Profiles')
    # Verify End Point Group is valid in the AP    
    if check_if_mo_exist(moDir,'uni/tn-' + fv_tenant.name + '/ap-'+ fv_ap.name + '/epg-', path_epg, AEPg, 'Application Endpoint Group', return_false=True, set_mo=False):
        uri = 'uni/tn-' + fv_tenant.name + '/ap-'+ fv_ap.name + '/epg-'
        fv_aepg = check_if_mo_exist(moDir, uri , path_epg, AEPg, return_false=False, set_mo=False)
    else:
        module.fail_json(msg= path_epg + ' application EPG does not exist. Check Tenants -> Tenant ' + fv_tenant.name + ' -> Application Profiles -> ' + fv_ap.name + ' -> Application EPGs' )
         
    if path_type == 'individual':
        # Get the node id of the leaf_profile
        try:
            if path_fex:
                node_id = get_nodeid(moDir, leaf_profile[:-8])
            else:
                node_id = get_nodeid(moDir, leaf_profile)
        except IndexError:
            module.fail_json(msg= 'unable to find Node.  Verify syntax.') 
        
        if node_id == '0':
            module.fail_json(msg= leaf_profile + ' does not have a node id.')            
        
        if path_fex:
            path = 'topology/pod-1/paths-' + node_id + '/extpaths-' + path_fex +  '/pathep-[eth' + path_port + ']'
        else:
            path = 'topology/pod-1/paths-' + node_id + '/pathep-[eth' + path_port + ']'
    # if adding a port-channel          
    elif path_type == 'pc':
        try:
            if path_fex:
                node_id = get_nodeid(moDir, leaf_profile[:-8])
            else:
                node_id = get_nodeid(moDir, leaf_profile)
        except IndexError:
            module.fail_json(msg= 'unable to find Node.  Verify syntax.') 
        
        aep = get_policy_group_aep(moDir, path_name, 'accbundle-')
        
        if node_id == '0':
            module.fail_json(msg= leaf_profile + ' does not have a node id.')
        
        if path_fex:
            path = 'topology/pod-1/paths-' + node_id + '/extpaths-' + path_fex +  '/pathep-[' + path_name + ']'
        else:
            path = 'topology/pod-1/paths-' + node_id + '/pathep-[' + path_name + ']'

    # if adding a virtual port-channel                                   
    elif path_type == 'vpc':
        # check for vpc switch ids
        try:
            node_ids = get_vpcnodeid(moDir, leaf_profile)
        except IndexError:
            module.fail_json(msg= 'unable to find Node.  Verify syntax.') 
        
        if node_ids == '0':
            module.fail_json(msg= leaf_profile + ' is not a valid VPC domain.')
        
        if path_fex:
            path = 'topology/pod-1/protpaths-' + node_ids + '/extpaths-' + path_fex +  '/pathep-[' + path_name + ']'
        else:
            path = 'topology/pod-1/protpaths-' + node_ids + '/pathep-[' + path_name + ']'
                   
    else:
        module.fail_json(msg='Invalid interface type.  Options are "individual", "pc", or "vpc"')
    
    if state == 'present':
        if check_if_port_in_epg(moDir, 'uni/tn-' + fv_tenant.name + '/ap-'+ fv_ap.name + '/epg-' + fv_aepg.name + '/rspathAtt-[' + path + ']', path_mode, path_encap):
            module.fail_json(msg= 'Port already in EPG with conflicting configuration')
        if path_fex and path_type == 'individual':
            fex_profile = leaf_profile
            
            if check_if_mo_exist(moDir,'uni/infra/fexprof-', fex_profile, FexP, 'FEX Profile', return_false=True, set_mo=False):
                if check_if_fexport_configured(moDir, fex_profile, path_port):
                        port_name = get_fex_port_name(moDir, fex_profile, path_port)
                else:
                    module.fail_json(msg= 'Port is not configured in FEX Number ' + path_fex)
                
                if not port_name:
                    module.fail_json(msg = 'Port ' + path_port + ' is not configured.  Check Fabric -> Access Policies -> ' + fex_profile)
                
                policy_group = get_fexport_policy_group(moDir, fex_profile, port_name)
                if policy_group == '0':
                    module.fail_json(msg= 'Check Port Policy Group.')
                    
                aep = get_policy_group_aep(moDir, policy_group, 'accportgrp-')
        elif path_type == 'individual':
            if check_if_mo_exist(moDir,'uni/infra/accportprof-', leaf_profile + '_ifselector', AccPortP, 'Interface Profile', return_false=True, set_mo=False):
                if check_if_switchport_configured(moDir, leaf_profile, path_port):
                    port_name = get_switchport_name(moDir, leaf_profile, path_port)
            else:
                module.fail_json(msg= 'Port is not configured in Leaf Profile ' + leaf_profile)
            
            if not port_name:
                module.fail_json(msg = 'Port ' + path_port + ' is not configured.  Check Fabric -> Access Policies -> ' + leaf_profile + '_ifselector')
            
            policy_group = get_switchport_policy_group(moDir, leaf_profile, port_name)
            if policy_group == '0':
                module.fail_json(msg= 'Check Port Policy Group.')
                
            aep = get_policy_group_aep(moDir, policy_group, 'accportgrp-')
        else:
            if check_if_bundle_configured(moDir, path_name):
                aep = get_policy_group_aep(moDir, path_name, 'accbundle-')
            else:
                module.fail_json(msg= 'Bundle ' + path_name + ' on ' + leaf_profile + ' is not configured')
                
            if aep == '0':
                module.fail_json(msg= 'AEP not found for ' + path_name + ' path: ' + path)
         
            
        domains = get_epg_dom(moDir, uri, path_epg)
        aep_domain = False
        encap_domain = False
        for domain in domains:
            if check_policy_group_in_domain(moDir, domain, aep):
                aep_domain = True
                if check_static_vlan_in_domain(moDir, domain, path_encap):
                    encap_domain = True
                    fv_rsnodeatt = RsPathAtt(fv_aepg, path, descr=path_description, encap=path_encap, mode=path_mode, instrImedcy=path_immediancy)
                    break
        if not aep_domain:
            module.fail_json(msg= 'Policy group AEP domain does not match EPG.')
        if not encap_domain:
            module.fail_json(msg= 'Domain for ' + path_encap + ' is not in the EPG. Check Tenants -> Tenant ' + fv_tenant.name + ' -> Application Profiles -> ' + fv_ap.name + ' -> Application EPGs -> '+ fv_aepg.name + ' -> Domains')  
    
    #module will remove static port from epg
    elif state == 'absent':
        fv_rsnodeatt = check_if_mo_exist(moDir, uri+path_epg+'/rspathAtt-', '[' + path + ']', RsPathAtt, ' Static Port ', return_false=True, set_mo=False)
        if fv_rsnodeatt:
            fv_rsnodeatt.delete()
        else:
            module.fail_json(msg=' Path does not exist in AP ' + fv_ap.name + ' EPG ' + fv_aepg.name)
    else:       
        module.fail_json(msg='Invalid path status.  Options are "present" or "absent"')
        
    results = {}
    xmldoc = ''
    factsdict = {}
    changed = False
    
    # Build configuration and commit if not run in check-mode    
    if fv_aepg and state == 'present':
        xmldoc = print_query_xml(fv_aepg)
        factsdict['configuration'] = xmldoc
        if module.check_mode:
            module.exit_json(changed=True, ansible_facts=factsdict)
        else:
            changed = True
            commit_change(moDir, fv_aepg, print_xml=False)
    elif fv_rsnodeatt and state == 'absent':
        xmldoc = print_query_xml(fv_rsnodeatt)
        factsdict['configuration'] = xmldoc
        if module.check_mode:
            module.exit_json(changed=True, ansible_facts=factsdict)
        else:
            changed = True
            commit_change(moDir, fv_rsnodeatt, print_xml=False)

    results['xmldoc'] = xmldoc
    results['state'] = state
    results['changed'] = changed

    module.exit_json(ansible_facts=factsdict, **results)
    

from ansible.module_utils.basic import *
main()