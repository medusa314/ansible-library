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
version_added: "2.2"
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
from ansible.module_utils.six import string_types

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

def to_lines(stdout):
    for item in stdout:
        if isinstance(item, string_types):
            item = str(item).split('\n')
        yield item


def main():
    spec = dict(
        # { command: <str>, prompt: <str>, response: <str> }
        inside=dict(type='str', default=''),
        outside=dict(type='str', default=''),
        wait_for=dict(type='list', aliases=['waitfor']),
        match=dict(default='all', choices=['all', 'any']),

        retries=dict(default=10, type='int'),
        interval=dict(default=1, type='int')
    )

    spec.update(asa_argument_spec)

    module = AnsibleModule(argument_spec=spec, supports_check_mode=True)
    check_args(module)

    result = {'changed': False}

    wait_for = module.params['wait_for'] or list()
    conditionals = [Conditional(c) for c in wait_for]

    inside = module.params['inside']
    outside = module.params['outside']
    retries = module.params['retries']
    interval = module.params['interval']
    match = module.params['match']
    
    nats = []
    
    while retries > 0:
        if inside:
            inside_nat_command = ['show nat ' + inside]
            inside_response = run_commands(module, inside_nat_command)
            
            responses = inside_response[0].splitlines()
            
            for p in responses:
                if 'No matching NAT policy found' in p:
                    module.exit_json(msg=p)
            # Split the response to get the zone, and object names
                if 'Policies' in p or 'translate_hits' in p or len(p) < 6:
                    #module.fail_json(msg=p)
                    continue;
                if p.split()[5] == 'dynamic':
                    zone = p.split()[1][1:-1]
                    source_object = p.split()[6]
                    outside_object = p.split()[8]
                    type = 'dynamic'
                elif p.split()[5] == 'static':
                    zone = p.split()[1][1:-1]
                    source_object = p.split()[6]
                    outside_object = p.split()[7]
                    type = 'static'
                
            # check if outside object is actually an IP address from section 2
                try:
                    IPAddress(outside_object).is_unicast()
                    outside_ip = outside_object

                except core.AddrFormatError:
                    outside_object_command = ['show run object id ' + outside_object]
                    outside_object_response = run_commands(module, outside_object_command)
                    outside_ip = outside_object_response[0].splitlines()[1].strip()
                
                if source_object == 'any':
                    inside_ip = source_object
                else:
                    inside_object_command = ['show run object id ' + source_object]
                    inside_object_response = run_commands(module, inside_object_command)
                    inside_ip = inside_object_response[0].splitlines()[1].strip()
                    
                nats.append({'type': type, 'zone': zone, 'source_object': source_object, 'outside_object': outside_object, 'outside_ip': outside_ip, 'inside_ip': inside_ip})
                
            for item in list(conditionals):                    
                if item(inside_response):
                    if match == 'any':
                        conditionals = list()
                        break
                    conditionals.remove(item)
    
            if not conditionals:
                break
            
            time.sleep(interval)
            retries -= 1
                    
        if outside:    
            outside_nat_command = ['show nat translated ' + outside]        
            outside_response = run_commands(module, outside_nat_command)
            
            responses = outside_response[0].splitlines()
            
            for p in responses:
                if 'No matching NAT policy found' in p:
                    module.exit_json(msg=p)
            # Split the response to get the zone, and object names
                if 'Policies' in p or 'translate_hits' in p or len(p) < 6:
                    #module.fail_json(msg=p)
                    continue;
                if p.split()[5] == 'dynamic':
                    zone = p.split()[1][1:-1]
                    source_object = p.split()[6]
                    outside_object = p.split()[8]
                    type = 'dynamic'
                elif p.split()[5] == 'static':
                    zone = p.split()[1][1:-1]
                    source_object = p.split()[6]
                    outside_object = p.split()[7]
                    type = 'static'
                
            # check if outside object is actually an IP address from section 2
                try:
                    IPAddress(outside_object).is_unicast()
                    outside_ip = outside_object

                except core.AddrFormatError:
                    outside_object_command = ['show run object id ' + outside_object]
                    outside_object_response = run_commands(module, outside_object_command)
                    outside_ip = outside_object_response[0].splitlines()[1].strip()
                
                if source_object == 'any':
                    inside_ip = source_object
                else:
                    inside_object_command = ['show run object id ' + source_object]
                    inside_object_response = run_commands(module, inside_object_command)
                    inside_ip = inside_object_response[0].splitlines()[1].strip()
                    
                nats.append({'type': type, 'zone': zone, 'source_object': source_object, 'outside_object': outside_object, 'outside_ip': outside_ip, 'inside_ip': inside_ip})
            for item in list(conditionals):                    
                if item(outside_response):
                    if match == 'any':
                        conditionals = list()
                        break
                    conditionals.remove(item)
    
            if not conditionals:
                break
            
            time.sleep(interval)
            retries -= 1
    
    if conditionals:
        failed_conditions = [item.raw for item in conditionals]
        msg = 'One or more conditional statements have not be satisfied'
        module.fail_json(msg=msg, failed_conditions=failed_conditions)

    result.update({
        'changed': False,
        'results': nats
    })

    module.exit_json(**result)


if __name__ == '__main__':
    main()