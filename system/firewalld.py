#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2013, Adam Miller (maxamillion@fedoraproject.org)
# (c) 2015, Jakub Kramarz (jkramarz@virtuslab.com)
#
# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.

DOCUMENTATION = '''
---
module: firewalld
short_description: Manage arbitrary ports/services with firewalld
description:
  - This module allows for addition or deletion of services and ports either tcp or udp in either running or permanent firewalld rules.
version_added: "1.4"
options:
  service:
    description:
      - "Name of a service to add/remove to/from firewalld - service must be listed in /etc/services."
    required: false
    default: null
  port:
    description:
      - "Name of a port or port range to add/remove to/from firewalld. Must be in the form PORT/PROTOCOL or PORT-PORT/PROTOCOL for port ranges."
    required: false
    default: null
  rich_rule:
    description:
      - "Rich rule to add/remove to/from firewalld."
    required: false
    default: null
  masquerade:
    description:
      - "Anything, just to indicate operation on masquerade configuration"
    required: false
    default: null
  source:
    description:
      - "Source address to add/remove to/from firewalld"
    required: false
    default: null
  interface:
    description:
      - "Name of a interface to add/remove to/from firewalld"
    required: false
    default: null
  icmp_block:
    description:
      - "Name of a ICMP packet type to block/unblock."
    required: false
    default: null
  forward:
    description:
      - "Name of a port to forward from to add/remove to/from firewalld must be in the form PORT/PROTOCOL"
    required: false
    default: null
  to_addr:
    description:
      - "Forward destination IP address"
    required: false
    default: null
  to_port:
    description:
      - "Forward destination port"
    required: false
    default: null
  zone:
    description:
      - 'The firewalld zone to add/remove to/from (NOTE: default zone can be configured per system but "public" is default from upstream. Available choices can be extended based on per-system configs, listed here are "out of the box" defaults).'
    required: false
    default: system-default(public)
    choices: [ "work", "drop", "internal", "external", "trusted", "home", "dmz", "public", "block"]
  permanent:
    description:
      - "Should this configuration be in the running firewalld configuration or persist across reboots."
    required: true
  immediate:
    description:
      - "Should this configuration be applied immediately, if set as permanent"
    required: false
    default: false
    version_added: "1.9"
  state:
    description:
      - "Should this port accept(enabled) or reject(disabled) connections."
    required: true
  timeout:
    description:
      - "The amount of time the rule should be in effect for when non-permanent."
    required: false
    default: 0
  reload:
    description:
      - 'Perform firewall configuration reload after applying changes. Complete reload also looses state information.'
    required: false
    default: null
    choices: [ "config", "complete" ]
notes:
  - Not tested on any Debian based system.
requirements: [ 'firewalld >= 0.2.11' ]
author: '"Adam Miller (@maxamillion)" <maxamillion@fedoraproject.org>', '"Jakub Kramarz (@jkramarz)" <jkramarz@virtuslab.com>'
'''

EXAMPLES = '''
- firewalld: service=https permanent=true state=enabled
- firewalld: port=8081/tcp permanent=true state=disabled
- firewalld: port=161-162/udp permanent=true state=enabled
- firewalld: zone=dmz service=http permanent=true state=enabled
- firewalld: rich_rule='rule service name="ftp" audit limit value="1/m" accept' permanent=true state=enabled
- firewalld: zone=public masquerade=yes permanent=true state=enabled
- firewalld: zone=trusted interface=tun0 state=enabled reload=complete
- firewalld: forward=443/tcp to_addr=10.0.1.1 to_port=443 permanent=yes immediate=yes state=enabled
'''

import os
import re

try:
    import firewall.config
    FW_VERSION = firewall.config.VERSION

    from firewall.client import FirewallClient
    fw = FirewallClient()
    HAS_FIREWALLD = True
except ImportError:
    HAS_FIREWALLD = False


####################
# reload handling
#
def do_reload():
    fw.reload()

def do_complete_reload():
    fw.complete_reload()

################
# helper functions
#
def permanent_config_change(method, zone, *args):
    fw_zone = fw.config().getZoneByName(zone)
    fw_settings = fw_zone.getSettings()
    getattr(fw_settings, method)(*args)
    fw_zone.update(fw_settings)

def permanent_config_query(method, zone, *args):
    fw_zone = fw.config().getZoneByName(zone)
    fw_settings = fw_zone.getSettings()  
    return getattr(fw_settings, method)(*args)

def running_config_change(method, *args):
    getattr(fw, method)(*args)

def running_config_query(method, *args):
    return getattr(fw, method)(*args)
    
def action(
        msgs,
        module,

        message,

        query = None,
        enable = None,
        disable = None,

        permanent_query = None,
        permanent_enable = None,
        permanent_disable = None,
        running_query = None,
        running_enable = None,
        running_disable = None,

        args = None,
        permanent_query_args = None,
        permanent_enable_args = None,
        permanent_disable_args = None,
        running_query_args = None,
        running_enable_args = None,
        running_disable_args = None
    ):

    if module.params['state'] == 'enabled':
        desired_state = True
    else:
        desired_state = False
    permanent = module.params['permanent']
    immediate = module.params['immediate']

    changed = False

    if permanent_query is None:
        permanent_query = query
    if permanent_enable is None:
        permanent_enable = enable
    if permanent_disable is None:
        permanent_disable = disable

    if not callable(permanent_query):
        permanent_query_fun = (lambda *x: permanent_config_query(permanent_query, *x))
    else:
        permanent_query_fun = permanent_query
    if not callable(permanent_enable):
        permanent_enable_fun = (lambda *x: permanent_config_change(permanent_enable, *x))
    else:
        permanent_enable_fun = permanent_enable
    if not callable(permanent_disable):
        permanent_disable_fun = (lambda *x: permanent_config_change(permanent_disable, *x))
    else:
        permanent_disable_fun = permanent_disable

    if permanent_query_args is None:
        permanent_query_args = args
    if permanent_enable_args is None:
        permanent_enable_args = args
    if permanent_disable_args is None:
        permanent_disable_args = args

    if running_query is None:
        running_query = query
    if running_enable is None:
        running_enable = enable
    if running_disable is None:
        running_disable = disable

    if not callable(running_query):
        running_query_fun = (lambda *x: running_config_query(running_query, *x))
    else:
        running_query_fun = running_query
    if not callable(running_enable):
        running_enable_fun = (lambda *x: running_config_change(running_enable, *x))
    else:
        running_enable_fun = running_enable
    if not callable(running_disable):
        running_disable_fun = (lambda *x: running_config_change(running_disable, *x))
    else:
        running_disable_fun = running_disable

    if running_query_args is None:
        running_query_args = args
    if running_enable_args is None:
        running_enable_args = args
    if running_disable_args is None:
        running_disable_args = args

    if permanent:
        msgs.append('Permanent operation')
        is_enabled = permanent_query_fun(*permanent_query_args)
        if desired_state != is_enabled:
            if module.check_mode:
                module.exit_json(changed=True)
            else:
                if desired_state:
                    permanent_enable_fun(*permanent_enable_args)
                else:
                    permanent_disable_fun(*permanent_disable_args)
            changed = True

    if immediate or not permanent:
        msgs.append('Non-permanent operation')
        is_enabled = running_query_fun(*running_query_args)
        if desired_state != is_enabled:
            if module.check_mode:
                module.exit_json(changed=True)
            else:
                if desired_state:
                    running_enable_fun(*running_enable_args)
                else:
                    running_disable_fun(*running_disable_args)
            changed = True

    if changed:
        msgs.append(message)
    return changed


def main():

    module = AnsibleModule(
        argument_spec = dict(
            service=dict(required=False,default=None),
            port=dict(required=False,default=None),
            rich_rule=dict(required=False,default=None),
            masquerade=dict(required=False,default=None),
            source=dict(required=False,default=None),
            interface=dict(required=False,default=None),
            icmp_block=dict(required=False,default=None),
            to_port=dict(required=False,default=None),
            to_addr=dict(required=False,default=None),
            zone=dict(required=False,default=None),
            forward=dict(required=False,default=None),
            permanent=dict(type='bool',required=True),
            immediate=dict(type='bool',default=False),
            state=dict(choices=['enabled', 'disabled'], required=True),
            timeout=dict(type='int',required=False,default=0),
            reload=dict(choices=['config', 'complete'], required=False,default=None),
        ),
        supports_check_mode=True
    )

    if not HAS_FIREWALLD:
        module.fail_json(msg='firewalld required for this module')

    ## Pre-run version checking
    if FW_VERSION < "0.2.11":
        module.fail_json(msg='unsupported version of firewalld, requires >= 2.0.11')

    ## Global Vars
    changed=False
    msgs = []

    service = module.params['service']
    masquerade = module.params['masquerade']
    rich_rule = module.params['rich_rule']
    interface = module.params['interface']
    source = module.params['source']
    to_addr = module.params['to_addr']
    to_port = str(module.params['to_port'])
    icmp_block = module.params['icmp_block']
    reload = module.params['reload']

    if module.params['port'] != None:
        port, protocol = module.params['port'].split('/')
        if protocol == None:
            module.fail_json(msg='improper port format (missing protocol?)')
    else:
        port = None

    if module.params['forward'] != None:
        forward_port, forward_protocol = module.params['forward'].split('/')
        if forward_protocol == None:
            module.fail_json(msg='improper forward format (missing protocol?)')
    else:
        forward_port = None

    if module.params['zone'] != None:
        zone = module.params['zone']
    else:
        zone = fw.getDefaultZone()

    permanent = module.params['permanent']
    desired_state = module.params['state']
    immediate = module.params['immediate']
    timeout = module.params['timeout']

    ## Check for firewalld running
    try:
        if fw.connected == False:
            module.fail_json(msg='firewalld service must be running')
    except AttributeError:
        module.fail_json(msg="firewalld connection can't be established,\
                version likely too old. Requires firewalld >= 2.0.11")

    exclusive_operations = ('service', 'port', 'rich_rule', 'masquerade', 'source', 'interface', 'icmp_block', 'forward')
    modification_count = sum(
        map(
            lambda x: module.params[x] != None,
            exclusive_operations
        )
    )

    if modification_count > 1:
        module.fail_json(msg='can only simultaneously operate on one of the following: %s' % (', '.join(exclusive_operations)))

    perform_action = lambda **x: action(msgs, module, **x)

    if service != None:
        changed = perform_action(
            message                = "Changed service %s to %s" % (service, desired_state),
            args                   = (zone, service),

            query                  = 'queryService',
            enable                 = 'addService',
            disable                = 'removeService',

            running_enable_args    = (zone, service, timeout),
        )

    if port != None:
        changed = perform_action(
            message                = "Changed port %s to %s" % ("%s/%s" % (port, protocol), desired_state),
            args                   = (zone, port, protocol),

            query                  = 'queryPort',
            enable                 = 'addPort',
            disable                = 'removePort',

            running_enable_args    = (zone, port, protocol, timeout),
        )

    if rich_rule != None:
        changed = perform_action(
            message                = "Changed rich_rule %s to %s" % (rich_rule, desired_state),
            args                   = (zone, rich_rule),

            query                  = 'queryRichRule',
            enable                 = 'addRichRule',
            disable                = 'removeRichRule',

            running_enable_args    = (zone, rule, timeout),
        )

    if masquerade != None:
        changed = perform_action(
            message                = "Changed masquerade to %s" % (desired_state),
            args                   = [zone],

            permanent_query        = 'getMasquerade',
            running_query          = 'queryMasquerade',

            permanent_enable       = 'setMasquerade',
            permanent_enable_args  = (zone, True),
            permanent_disable      = 'setMasquerade',
            permanent_disable_args = (zone, False),

            running_enable         = 'addMasquerade',
            running_disable        = 'removeMasquerade'
        )

    if interface != None:
        changed = perform_action(
            message                = "Changed interface %s to %s" % (interface, desired_state),
            args                   = (zone, interface),

            query                  = 'queryInterface',
            enable                 = 'addInterface',
            disable                = 'removeInterface',
        )

    if source != None:
        changed = perform_action(
            message                = "Changed source %s to %s" % (source, desired_state),
            args                   = (zone, source),

            query                  = 'querySource',
            enable                 = 'addSource',
            disable                = 'removeSource',

        )

    if icmp_block != None:
        changed = perform_action(
            message                = "Changed icmp_block %s to %s" % (icmp_block, desired_state),
            args                   = (zone, icmp_block),

            query                  = 'queryIcmpBlock',
            enable                 = 'addIcmpBlock',
            disable                = 'removeIcmpBlock',

            running_enable_args    = (zone, icmp_block, timeout),
        )

    if forward_port != None:
        changed = perform_action(
            message                = "Changed forward from %s to %s:%s to state %s" % ("%s/%s" % (forward_port, forward_protocol), to_addr, to_port, desired_state),
            args                   = (zone, forward_port, forward_protocol, to_port, to_addr),

            query                  = 'queryForwardPort',
            enable                 = 'addForwardPort',
            disable                = 'removeForwardPort',

            running_enable_args    = (zone, forward_port, forward_protocol, to_port, to_addr, timeout),
        )

    if reload != None:
        if module.check_mode:
            module.exit_json(changed=True)
        if reload == "complete":
            do_complete_reload()
        else:
            do_reload()
        changed=True
        msgs.append("Configuration reloaded")

    module.exit_json(changed=changed, msg=', '.join(msgs))

#################################################
# import module snippets
from ansible.module_utils.basic import *
main()
