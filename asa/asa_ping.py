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
  dest:
    description:
      - the destination to ping
    required: true
  interface:
    description:
      - the ASA interface to ping from
  count:
    description:
      - the number of ICMP to send
    default: 5
  size:
    description:
      - datagram size, in bytes. Minimum is 28, maximum is 65535
  data:
    description:
      - the hex data string to send.  <0-ffff>
  timeout:
    description:
      - the time to wait for a response, in seconds.  Minimum is 0, maximum is 3600
  validate:
    description:
      - whether the ASA should validate the response
    default: False
    choices: ['True', 'False']
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
- asa_ping:
    dest: '10.93.108.115' 
    provider: "{{ cli }}"
    
- asa_ping:
    dest: '10.93.108.115'
    interface: 'inside'
    count: 2
    size: 1500
    validate: True
    provider: "{{ cli }}"    
"""

RETURN = """
commands:
  description: the list commands that were sent to the ASA
  returned: when found
  type: list
  sample: ['ping 10.93.108.115', 'ping inside 10.93.108.115 count 2 size 1500 validate']
results:
  description: the list of the ping results
  returned: when found
  type: list
  sample: [{'destination': '10.93.108.115', 'packet_loss': '0%', 'packets_rx': 5, 'packets_tx': 5, 'rtt':{'avg':1, 'max':1, 'min':1}]
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

def build_ping(dest, count=None, interface=None, data=None, size=None, timeout=None, validate=False):
    """
    Function to build the command to send to the terminal for the switch
    to execute. All args come from the module's unique params.
    """
    if interface is not None:
        cmd = "ping {0} {1}".format(interface, dest)
    else:
        cmd = "ping {0}".format(dest)

    if count is not None and count >=1 and count <= 2147483647:
        cmd += " repeat {0}".format(str(count))

    if data is not None:
        try:
            hex_data = int(data, 16)
            cmd += " data {0}".format(source)
        except ValueError:
            data = None
        
    if size is not None and size >= 28 and size <= 65535:
        cmd += " size {0}".format(str(size))
    
    if timeout is not None and timeout >= 0 and timeout <= 3600:
        cmd += " timeout {0}".format(str(timeout))
    
    if validate:
        cmd += " validate"
    
    return cmd

def parse_ping(ping_stats):
    """
    Function used to parse the statistical information from the ping response.
    Example: "Success rate is 100 percent (5/5), round-trip min/avg/max = 1/2/8 ms"
    Returns the percent of packet loss, recieved packets, transmitted packets, and RTT dict.
    """
    rate_re = re.compile(r"^\w+\s+\w+\s+\w+\s+(?P<pct>\d+)\s+\w+\s+\((?P<rx>\d+)/(?P<tx>\d+)\)")
    rtt_re = re.compile(r".*,\s+\S+\s+\S+\s+=\s+(?P<min>\d+)/(?P<avg>\d+)/(?P<max>\d+)\s+\w+\s*$|.*\s*$")

    rate = rate_re.match(ping_stats)
    rtt = rtt_re.match(ping_stats)

    return rate.group("pct"), rate.group("rx"), rate.group("tx"), rtt.groupdict()


def validate_results(module, loss, result):
    """
    This function is used to validate whether the ping results were unexpected per "state" param.
    """
    state = module.params["state"]
    if state == "present" and loss == 100:
        return "Ping failed unexpectedly"
    elif state == "absent" and loss < 100:
        return "Ping succeeded unexpectedly"

def main():
    spec = dict(
        # { command: <str>, prompt: <str>, response: <str> }
        count=dict(type="int"),
        size=dict(type="size"),
        dest=dict(type="str", required=True),
        interface=dict(type="str"),
        data=dict(type="str"),
        timeout=dict(type="str"),
        validate=dict(type="bool"),
        state=dict(type="str", choices=["absent", "present"], default="present"),
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

    count = module.params['count']
    dest = module.params['dest']
    interface = module.params['interface']
    data = module.params['data']
    size = module.params['size']
    validate = module.params['validate']
    timeout = module.params['timeout']
    retries = module.params['retries']
    interval = module.params['interval']
    match = module.params['match']
    
    
    while retries > 0:
        cmds = []
        try:
            dest_ping = IPSet([IPNetwork(dest)])
            for dst in dest_ping:
                cmds.append(build_ping(str(dst), count, interface, data, size, timeout, validate))
        except core.AddrFormatError:
            cmds.append(build_ping(dest, count, interface, data, size, timeout, validate))
        
        result["commands"] = cmds
        
        ping_results = run_commands(module, commands=result["commands"])
        result["results"] = []
        
        for ping_result in ping_results:
            destination_result = {}
            ping_results_list = ping_result.splitlines()
            
            stats = ""
            for line in ping_results_list:
                if line.startswith('Success'):
                    stats = line
                elif line.startswith('Sending'):
                    destination_result['destination'] = line.split(',')[1].split('to')[1]
            
            if stats:
                success, rx, tx, rtt = parse_ping(stats)
                loss = abs(100 - int(success))
                destination_result["packet_loss"] = str(loss) + "%"
                destination_result["packets_rx"] = int(rx)
                destination_result["packets_tx"] = int(tx)
                
                # Convert rtt values to int
                for k, v in rtt.items():
                    if rtt[k] is not None:
                        rtt[k] = int(v)
        
                destination_result["rtt"] = rtt
                
                destination_result["msg"] = validate_results(module, loss, result)
                result["results"].append(destination_result)
        
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
                    
        
    
    if conditionals:
        failed_conditions = [item.raw for item in conditionals]
        msg = 'One or more conditional statements have not be satisfied'
        module.fail_json(msg=msg, failed_conditions=failed_conditions)

    module.exit_json(**result)


if __name__ == '__main__':
    main()