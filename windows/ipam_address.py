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
    numberOfAddresses:
        description:
            - the number of addresses required
        required: false
        default: 1
        aliases: []
    customConfiguration:
        description:
            - IPAM custom field string.
        required: false
        default: null
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
ipam_address: 
  startRange: 204.154.41.128
  endRange: 204.154.41.159
  numberOfAddresses: 2
  
ipam_address: 
  customConfiguration: "VRF=vrf-1;Site=DC1"
  addressCategory: public
  
ipam_address: 
  ip: 204.154.41.128
  state: query
  
ipam_setaddress:
  ip: 64.68.39.224
  description: PUBLIC_TEST-HOST-1
'''
RETURN = '''
changed:
    description:  Whether or not changed
    returned: True
    type: bool
    sample: True
failed:
    description:  Whether or not failed
    returned: True
    type: bool
    sample: False
ip:
    description:  IP address
    returned: True
    type: string
    sample: 10.1.1.2
description:
    description:  IPAM IPAddress description
    returned: True
    type: string
    sample: "TEST-HOST"
startRange:
    description:  start of the range the IP address belongs to
    returned: True
    type: string
    sample: "10.1.1.1"
endRange:
    description:  end of the range the IP address belongs to
    returned: True
    type: string
    sample: "10.1.1.254"
range:
    description:  the range the IP address belongs to and its attributes
    returned: True
    type: string
    sample: {"addresses": {"assigned": 70, "percentageUtilized": 50, "utilized": 35},"assignmentType": "Static","description": "DEVICE MGMT","managedByService": "IPAM"}
subnet:
    description:  the subnet the IP address belongs to and its attributes
    returned: True
    type: string
    sample: { "addressSpace": "Default", "addresses": {"assigned": 251, "percentageUtilized": 13.8671875, "utilized": 71 }, 
              "customConfiguration": {"City": "North City", "Site": "DC1", "VRF": "vrf-1"}, 
              "description": "security_subnet",  "name": "security_system",  "networkID": "10.1.1.0/24",  "networkType": "NonVirtualized", 
              "overlap": false,  "owner": "Security",  "totalAddresses": 256,  "vlan": [4] }
category:
    description:  whether IP is public or private
    returned: True
    type: string
    sample: "private"
msg:
    description:  user message indicating return status
    returned: True
    type: string
    sample: "query successful"
'''