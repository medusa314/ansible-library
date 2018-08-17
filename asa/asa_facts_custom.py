#!/usr/bin/env python2.7

# Copyright (c) 2018 Sybil Melton, Dominion Enterprises
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}


DOCUMENTATION = """
---
module: asa_nat
version_added: "2.5"
author: "Sybil Melton"
short_description: Find NAT on ASA
description:
  - Sends commands to an ASA node and returns the NAT results
extends_documentation_fragment: asa
options:
  ip:
    description:
      - IP to search NAT for
    required: true
  wait_for:
    description:
      - List of conditions to evaluate against the output of the
        command. The task will wait for each condition to be true
        before moving forward. If the conditional is not true
        within the configured number of retries, the task fails.
        See examples.
    aliases: ['waitfor']
  match:
    description:
      - The I(match) argument is used in conjunction with the
        I(wait_for) argument to specify the match policy.  Valid
        values are C(all) or C(any).  If the value is set to C(all)
        then all conditionals in the wait_for must be satisfied.  If
        the value is set to C(any) then only one of the values must be
        satisfied.
    default: all
    choices: ['any', 'all']
  retries:
    description:
      - Specifies the number of retries a command should by tried
        before it is considered failed. The command is run on the
        target device every retry and evaluated against the
        I(wait_for) conditions.
    default: 10
  interval:
    description:
      - Configures the interval in seconds to wait between retries
        of the command. If the command does not pass the specified
        conditions, the interval indicates how long to wait before
        trying the command again.
    default: 1
"""

EXAMPLES = """
# Note: examples below use the following provider dict to handle
#       transport and authentication to the node.
---
vars:
  cli:
    host: "{{ inventory_hostname }}"
    username: cisco
    password: cisco
    authorize: yes
    auth_pass: cisco
    transport: cli
---
- asa_nat:
    inside: '10.93.108.115' 
    provider: "{{ cli }}"
- asa_command:
    outside: '204.154.42.76'
    provider: "{{ cli }}"
"""

RETURN = """
result:
  description: the list of NATs found in the ASA
  returned: when found
  type: list
  sample: ['...', '...']
failed_conditions:
  description: the conditionals that failed
  returned: failed
  type: list
  sample: ['...', '...']
"""
import time
import re
from netaddr import *

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.network.asa.asa import asa_argument_spec, check_args
from ansible.module_utils.network.asa.asa import run_commands
from ansible.module_utils.network.common.parsing import Conditional
from ansible.module_utils.six import string_types, iteritems

# STD REGEX PATTERNS
IP_ADDR_REGEX = r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
IPV4_ADDR_REGEX = IP_ADDR_REGEX
IPV6_ADDR_REGEX_1 = r"::"
IPV6_ADDR_REGEX_2 = r"[0-9a-fA-F:]{1,39}::[0-9a-fA-F:]{1,39}"
IPV6_ADDR_REGEX_3 = r"[0-9a-fA-F]{1,4}:[0-9a-fA-F]{1,4}:[0-9a-fA-F]{1,4}:[0-9a-fA-F]{1,4}:" \
                     "[0-9a-fA-F]{1,4}:[0-9a-fA-F]{1,4}:[0-9a-fA-F]{1,4}:[0-9a-fA-F]{1,4}"
# Should validate IPv6 address using an IP address library after matching with this regex
IPV6_ADDR_REGEX = "(?:{}|{}|{})".format(IPV6_ADDR_REGEX_1, IPV6_ADDR_REGEX_2, IPV6_ADDR_REGEX_3)

MAC_REGEX = r"[a-fA-F0-9]{4}\.[a-fA-F0-9]{4}\.[a-fA-F0-9]{4}"
VLAN_REGEX = r"\d{1,4}"
INT_REGEX = r"(^\w{1,2}\d{1,3}/\d{1,2}|^\w{1,2}\d{1,3})"
RE_IPADDR = re.compile(r"{}".format(IP_ADDR_REGEX))
RE_IPADDR_STRIP = re.compile(r"({})\n".format(IP_ADDR_REGEX))
RE_MAC = re.compile(r"{}".format(MAC_REGEX))


class FactsBase(object):

    def __init__(self, module):
        self.module = module
        self.warnings = list()
        self.facts = dict()

    def populate(self):
        pass

    def run(self, command):
        command_string = command
        command = {
            'command': command
        }
        resp = run_commands(self.module, [command])
        try:
            return resp[0]
        except IndexError:
            self.warnings.append('command %s failed, facts will not be populated' % command_string)
            return None

    def transform_dict(self, data, keymap):
        transform = dict()
        for key, fact in keymap:
            if key in data:
                transform[fact] = data[key]
        return transform

    def transform_iterable(self, iterable, keymap):
        for item in iterable:
            yield self.transform_dict(item, keymap)


class Default(FactsBase):
    def populate(self):
        data = self.run('show version')
        responses = data.splitlines()
        #return responses
        result = {}
        for p in responses:
            if p.find('Cisco Adaptive Security Appliance Software Version') >= 0:
                result['version'] = p.split()[6].strip()
            elif p.find('Device Manager Version') >= 0:
                result['asdm'] = p.split()[3].strip()
            elif p.find('REST API Agent Version') >= 0:
                result['rest'] = p.split()[4].strip()
            elif p.find('Serial Number:') >= 0:
                result['serialnum'] = p.split()[2].strip()
            elif p.find(' up ') >= 0 and p.find('failover cluster') < 0:
                result['host_name'] = p.split()[0].strip()
            elif p.find('Hardware:') >= 0:
                try:
                    chassis = p.split(':')[1].split(',')[0].strip()
                except IndexError:
                    chassis = p.split()[1].strip()
                result['chassis_id'] = chassis
        
        data = self.run('show firewall')
        responses = data.splitlines()
        for p in responses:
            if p.find('Firewall') >= 0:
                result['fw_mode'] = p.split(':')[1].strip()
        
        if result.get('version'):
            self.facts.update(result)
        else:
            self.warnings.append('version failed, facts will not be populated')
        
        context = {}
        data = self.run('show mode')
        responses = data.splitlines()
        if(responses[0].find('Security context') >= 0):
            context['context_mode'] = responses[0].split(':')[1].strip()
        
        if context['context_mode'] == 'multiple':
            data = self.run('show context detail')
            responses = data.splitlines()
            for c in responses:
                if c.find('Context') >= 0:
                    context['context'] = c.split()[1][1:][:-2]
        
        if context.get('context_mode'):
            self.facts.update(context)
        else:
            self.warnings.append('context failed, facts will not be populated')
        
        
        
class Config(FactsBase):

    def populate(self):
        super(Config, self).populate()
        '''
        self.facts['config'] = get_config(self.module)
        '''


class Hardware(FactsBase):

    def populate(self):
        
        data = self.run('dir')
        if data:
            responses = data.splitlines()
            responses(len())
            self.facts['filesystems'] = self.parse_filesystems(data)

        data = self.run('show system resources')
        responses = data.splitlines()
        result = {}
        for s in responses:
            try:
                if s.split()[0] == 'Memory':
                    self.facts['memtotal_mb'] = int(s.split()[2][:-1])
                    self.facts['memfree_mb'] = int(s.split()[6][:-1])
            except IndexError:
                continue

    

class Interfaces(FactsBase):

    INTERFACE_MAP = frozenset([
        ('state', 'state'),
        ('desc', 'description'),
        ('eth_bw', 'bandwidth'),
        ('eth_duplex', 'duplex'),
        ('eth_speed', 'speed'),
        ('eth_mode', 'mode'),
        ('eth_hw_addr', 'macaddress'),
        ('eth_mtu', 'mtu'),
        ('eth_hw_desc', 'type')
    ])

    INTERFACE_SVI_MAP = frozenset([
        ('svi_line_proto', 'state'),
        ('svi_bw', 'bandwidth'),
        ('svi_mac', 'macaddress'),
        ('svi_mtu', 'mtu'),
        ('type', 'type')
    ])

    INTERFACE_IPV4_MAP = frozenset([
        ('eth_ip_addr', 'address'),
        ('eth_ip_mask', 'masklen')
    ])

    INTERFACE_SVI_IPV4_MAP = frozenset([
        ('svi_ip_addr', 'address'),
        ('svi_ip_mask', 'masklen')
    ])

    INTERFACE_IPV6_MAP = frozenset([
        ('addr', 'address'),
        ('prefix', 'subnet')
    ])
    
    def populate(self):
        self.facts['all_ipv4_addresses'] = list()
        self.facts['all_ipv6_addresses'] = list()

        data = self.run('show interface detail')
        if data:
            self.facts['interfaces'] = self.populate_interfaces(data)    


    def populate_interfaces(self, data):
        interfaces = dict()
        
        responses = data.splitlines()        
        intf = dict()
        name = 'port'
        for i in responses:
            if i.find('line protocol') >= 0:
                intf = dict()
                intf['nameif'] = i.split(',')[0].split()[2].strip("\"")
                name = i.split(',')[0].split()[1]
                intf['state'] = i.split(',')[1].split(' is')[1].strip()
                interfaces[name] = intf
            elif i.strip().find('MAC address') == 0:
                interfaces[name].update({'macaddress':  i.split(',')[0].split()[2]})
                mtu = i.split(',')[1].split()[1]
                if mtu != 'not':
                    interfaces[name].update({'mtu': mtu})
            elif i.find('Hardware') >= 0:
                interfaces[name].update({'type':  i.split(',')[0].split('is')[1].strip()})
                interfaces[name].update({'bandwidth':  i.split(',')[1].split()[1] + " " + i.split(',')[1].split()[2]})
            elif i.find('-duplex') >= 0:
                interfaces[name].update({'duplex': i.split(',')[0].strip()})
                interfaces[name].update({'speed' : i.split(',')[1].strip()})
            elif i.find('Active member of') >= 0:
                interfaces[name].update({'parent':  i.split()[3]})
            elif i.find('IP address ') >= 0:
                addr = i.split(',')[0].split()[2].strip()
                if addr != 'unassigned' and addr != '127.0.0.1':
                    mask = i.split('subnet mask')[1].strip()
                    ip = IPNetwork(addr + '/' + mask)
                    interfaces[name].update({'ipv4': [{'address': addr, 'masklen': ip.prefixlen}]})
                    self.facts['all_ipv4_addresses'].append(addr)           
            elif i.find('Description:') >= 0:
                interfaces[name].update({'description': i.split(':')[1].strip()})
            elif i.find('VLAN identifier') >= 0:
                interfaces[name].update({'vlan':  i.split()[2]})
            elif i.find('Vlan') >= 0:
                interfaces[name].update({'vlan':  i.split()[2][4:]})
            
                
        return interfaces



FACT_SUBSETS = dict(
    default=Default,
    hardware=Hardware,
    interfaces=Interfaces,
    config=Config,
)

VALID_SUBSETS = frozenset(FACT_SUBSETS.keys())


def main():
    spec = dict(
        wait_for=dict(type='list', aliases=['waitfor']),
        match=dict(default='all', choices=['all', 'any']),

        retries=dict(default=10, type='int'),
        interval=dict(default=1, type='int'),
        gather_subset=dict(default=['!config'], type='list')
    )

    spec.update(asa_argument_spec)

    module = AnsibleModule(argument_spec=spec, supports_check_mode=True)
    
    warnings = list()
    check_args(module)
    
    wait_for = module.params['wait_for'] or list()
    conditionals = [Conditional(c) for c in wait_for]
    
    gather_subset = module.params['gather_subset']
    retries = module.params['retries']
    interval = module.params['interval']
    match = module.params['match']
    
    runable_subsets = set()
    exclude_subsets = set()

    for subset in gather_subset:
        if subset == 'all':
            runable_subsets.update(VALID_SUBSETS)
            continue

        if subset.startswith('!'):
            subset = subset[1:]
            if subset == 'all':
                exclude_subsets.update(VALID_SUBSETS)
                continue
            exclude = True
        else:
            exclude = False

        if subset not in VALID_SUBSETS:
            module.fail_json(msg='Bad subset')

        if exclude:
            exclude_subsets.add(subset)
        else:
            runable_subsets.add(subset)

    if not runable_subsets:
        runable_subsets.update(VALID_SUBSETS)

    runable_subsets.difference_update(exclude_subsets)
    runable_subsets.add('default')

    facts = dict()
    facts['gather_subset'] = list(runable_subsets)

    instances = list()
    for key in runable_subsets:
        instances.append(FACT_SUBSETS[key](module))

    for inst in instances:
        #results = dict()
        #results['result'] = inst.populate()
        #module.exit_json(**results)
        inst.populate()
        facts.update(inst.facts)
        warnings.extend(inst.warnings)

    ansible_facts = dict()
    for key, value in iteritems(facts):
        # this is to maintain capability with nxos_facts 2.1
        if key.startswith('_'):
            ansible_facts[key[1:]] = value
        else:
            key = 'ansible_net_%s' % key
            ansible_facts[key] = value

    module.exit_json(ansible_facts=ansible_facts, warnings=warnings)


if __name__ == '__main__':
    main()
