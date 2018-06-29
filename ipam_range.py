#!/usr/local/bin/python

# Copyright (c) 2017 Sybil Melton, Dominion Enterprises
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = '''
---

module: ipam_range
short_description: Query, Add, Delete IPAM ranges
description:
    - Offers ability to finds a free IP range, delete a range, and to query if a range in Windows IPAM
author: Sybil Melton
requirements:
    - Windows IpamServer
    - winrm
options:
    subnet
        description:
            - Subnet the range will be created in
        required: false
        default: null
        choices: []
        aliases: []
    size
        description:
            - Size of the range to be created
        required: false
        default: null
        choices: []
        aliases: []
    name
        description:
            - Name of the range
        required: false
        default: null
        choices: []
        aliases: []
    removeIP
        description:
            - Signifies if IPs will be removed when a range is deleted
        required: false
        default: null
        choices: []
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
    state:
        description:
            - Desired state
        required: false
        default: present
        choices: ['present','absent']
        aliases: []
'''
EXAMPLES = '''
ipam_getrange: 
  startRange: 204.154.41.128
  endRange: 204.154.41.159
  state: query
  
ipam_getrange: 
  subnet: "10.94.32.0/23"
  size: 8
  name: "TEST RANGE"
  
ipam_getrange: 
  startRange: 10.94.32.28
  endRange: 10.94.32.35
  state: absent
'''
RETURN = '''
changed:
    description:  Whether or not changed
    returned: True
    type: string
    sample: True
startRange:
    description:  start of the range
    returned: True
    type: string
    sample: 10.1.1.1
endRange:
    description:  end of the range
    returned: True
    type: string
    sample: 10.1.1.254
subnet:
    description:  the network the range belongs to
    returned: True
    type: string
    sample: 10.1.1.0/24
rangeName:
    description:  the name of the range
    returned: True
    type: string
    sample: DS-NET-ANSIBLE
size:
    description:  the number of assigned addresses
    returned: True
    type: string
    sample: 8
used:
    description:  the number of utilized addresses
    returned: True
    type: string
    sample: 3
percentUtilized:
    description:  the percentage of utilized addresses
    returned: True
    type: string
    sample: 75
'''