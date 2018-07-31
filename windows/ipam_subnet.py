#!/usr/local/bin/python

# Copyright (c) 2017 Sybil Melton, Dominion Enterprises
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = '''
---

module: ipam_subnet
short_description: Queries IPAM for subnets
description:
    - Offers the ability to query IPAM for an existing subnet
author: Sybil Melton
requirements:
    - Windows IpamServer
    - winrm
options:
    network:
        description:
                - The NetworkId
            required: false
            default: null
            choices: []
            aliases: []
    subnetName:
        description:
            - Name of the subnet
        required: false
        default: null
        choices: []
        aliases: []
    addressCategory:
        description:
            - category of IP addresses to search
        required: false
        default: private
        choices: ['public','private']
        aliases: []
    addressFamily:
        description:
            - family of IP addresses to search
        required: false
        default: IPv4
        choices: ['IPv4','IPv6']
        aliases: []
    context:
        description:
            - Custom Configuration - firewall context; provide with site
        required: false
        default: null
        choices: []
        aliases: []
    site:
        description:
            - Custom Configuration - device site; provide with context
        required: true
        default: null
        choices: []
        aliases: []
    state:
        description:
            - Desired state
        required: false
        default: present
        choices: ['present','absent','query']
        aliases: []
'''
EXAMPLES = '''
ipam_getsubnet: 
  network: 10.93.112.0/24
  state: query
  
ipam_getsubnet: 
  context: DHS
  site: DS
  
ipam_getsubnet:  
  subnetName: services_inside
  state: query
'''
RETURN = '''
changed:
    description:  Whether or not changed
    returned: True
    type: string
    sample: True
context:
    description:  Firewall context the IP address is routed to
    returned: True
    type: string
    sample: DHS
site:
    description:  Site designator
    returned: True
    type: string
    sample: DS
city:
    description:  geological city
    returned: True
    type: string
    sample: Norfolk
name:
    description:  the name of the subnet
    returned: True
    type: string
    sample: services_dmz
networkID:
    description:  network and subnet mask
    returned: True
    type: string
    sample: 10.93.112.0/24
'''