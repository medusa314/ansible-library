#!/usr/local/bin/python

# Copyright (c) 2017 Sybil Melton, Dominion Enterprises
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = '''
---

module: ipam_address
short_description: Windows IPAM IPAddress module
description:
    - Offers ability to finds a free IP address, query if an IP exists in Windows IPAM, create and modify existing IP Addresses
author: Sybil Melton
requirements:
    - Windows IpamServer
    - winrm
options:
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
    startRange:
        description:
            - The start of the range; provide with endRange
        required: false
        default: null
        choices: []
        aliases: []
    endRange:
        description:
            - The end of the range; provide with startRange
        required: false
        default: null
        choices: []
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
    ip:
        description:
            - The IP address to search for
        required: true
        default: null
        choices: []
        aliases: []
    description:
        description:
            - IP address description
        required: false
        default: "host"
        choices: []
        aliases: []
    deviceType:
        description:
            - Type of device.  
        required: false
        default: "Host"
        choices: ["Host","Load balancer","Firewall","Routers","Printer","Switch","VM","VPN","Wireless AP","Wireless controller"]
        aliases: []
    service:
        description:
            - IPAM service.  
        required: false
        default: "IPAM"
        choices: ["IPAM","MS DHCP","Non-MS DHCP","Others","VMM"]
        aliases: []
    ipAddressState:
        description:
            - IP address state.
        required: false
        default: "In-Use"
        choices: ["In-Use","Inactive","Reserved"]
        aliases: []
    instance:
        description:
            - IPAM service instance.
        required: false
        default: "localhost"
        choices: []
        aliases: []
    type:
        description:
            - IPAM address type
        required: false
        default: "Static"
        choices: ["Static","Dynamic"]
        aliases: []
    state:
        description:
            - Desired state
        required: false
        default: present
        choices: ['present','absent','query','create','modify']
        aliases: []
'''
EXAMPLES = '''
ipam_getaddress: 
  startRange: 204.154.41.128
  endRange: 204.154.41.159
  
ipam_getaddress: 
  context: DHS
  site: DS
  addressCategory: public
  
ipam_getaddress: 
  ip: 204.154.41.128
  state: query
  
ipam_setaddress:
  ip: 64.68.39.224
  description: PUBLIC_TEST-HOST-1
  state: create
'''
RETURN = '''
changed:
    description:  Whether or not changed
    returned: True
    type: string
    sample: True
ip:
    description:  Free IP address found
    returned: True
    type: string
    sample: 10.1.1.2
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
startRange:
    description:  start of the range the IP address belongs to
    returned: True
    type: string
    sample: 10.1.1.1
endRange:
    description:  end of the range the IP address belongs to
    returned: True
    type: string
    sample: 10.1.1.254
subnetName:
    description:  the name of the subnet
    returned: True
    type: string
    sample: services_dmz
rangeName:
    description:  the name of the range
    returned: True
    type: string
    sample: DS-NS-INT
category:
    description:  whether IP is public or private
    returned: True
    type: string
    sample: private
'''