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
  interface:
    description:
      - "Name of a interface to add/remove to/from firewalld"
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
notes:
  - Not tested on any Debian based system.
requirements: [ 'firewalld >= 0.2.11' ]
author: '"Adam Miller (@maxamillion)" <maxamillion@fedoraproject.org>'
'''

EXAMPLES = '''
- firewalld: service=https permanent=true state=enabled
- firewalld: port=8081/tcp permanent=true state=disabled
- firewalld: port=161-162/udp permanent=true state=enabled
- firewalld: zone=dmz service=http permanent=true state=enabled
- firewalld: rich_rule='rule service name="ftp" audit limit value="1/m" accept' permanent=true state=enabled
- firewalld: zone=public masquerade=yes permanent=true state=enabled
- firewalld: zone=trusted interface=tun0 state=enabled
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

################
# port handling
#
def get_port_enabled(zone, port_proto):
    if port_proto in fw.getPorts(zone):
        return True
    else:
        return False

def set_port_enabled(zone, port, protocol, timeout):
    fw.addPort(zone, port, protocol, timeout)

def set_port_disabled(zone, port, protocol):
    fw.removePort(zone, port, protocol)

def get_port_enabled_permanent(zone, port_proto):
    fw_zone = fw.config().getZoneByName(zone)
    fw_settings = fw_zone.getSettings()
    if tuple(port_proto) in fw_settings.getPorts():
        return True
    else:
        return False

def set_port_enabled_permanent(zone, port, protocol):
    fw_zone = fw.config().getZoneByName(zone)
    fw_settings = fw_zone.getSettings()
    fw_settings.addPort(port, protocol)
    fw_zone.update(fw_settings)

def set_port_disabled_permanent(zone, port, protocol):
    fw_zone = fw.config().getZoneByName(zone)
    fw_settings = fw_zone.getSettings()
    fw_settings.removePort(port, protocol)
    fw_zone.update(fw_settings)
    

####################
# service handling
#
def get_service_enabled(zone, service):
    if service in fw.getServices(zone):
        return True
    else:
        return False

def set_service_enabled(zone, service, timeout):
    fw.addService(zone, service, timeout)

def set_service_disabled(zone, service):
    fw.removeService(zone, service)

def get_service_enabled_permanent(zone, service):
    fw_zone = fw.config().getZoneByName(zone)
    fw_settings = fw_zone.getSettings()
    if service in fw_settings.getServices():
        return True
    else:
        return False

def set_service_enabled_permanent(zone, service):
    fw_zone = fw.config().getZoneByName(zone)
    fw_settings = fw_zone.getSettings()
    fw_settings.addService(service)
    fw_zone.update(fw_settings)

def set_service_disabled_permanent(zone, service):
    fw_zone = fw.config().getZoneByName(zone)
    fw_settings = fw_zone.getSettings()
    fw_settings.removeService(service)
    fw_zone.update(fw_settings)
    

####################
# rich rule handling
#
def get_rich_rule_enabled(zone, rule):
    if rule in fw.getRichRules(zone):
        return True
    else:
        return False

def set_rich_rule_enabled(zone, rule, timeout):
    fw.addRichRule(zone, rule, timeout)

def set_rich_rule_disabled(zone, rule):
    fw.removeRichRule(zone, rule)

def get_rich_rule_enabled_permanent(zone, rule):
    fw_zone = fw.config().getZoneByName(zone)
    fw_settings = fw_zone.getSettings()
    if rule in fw_settings.getRichRules():
        return True
    else:
        return False

def set_rich_rule_enabled_permanent(zone, rule):
    fw_zone = fw.config().getZoneByName(zone)
    fw_settings = fw_zone.getSettings()
    fw_settings.addRichRule(rule)
    fw_zone.update(fw_settings)

def set_rich_rule_disabled_permanent(zone, rule):
    fw_zone = fw.config().getZoneByName(zone)
    fw_settings = fw_zone.getSettings()
    fw_settings.removeRichRule(rule)
    fw_zone.update(fw_settings)

####################
# masquerade handling
#
def get_masquerade_enabled(zone):
    return fw.queryMasquerade(zone)

def set_masquerade_enabled(zone):
    fw.addMasquerade(zone)

def set_masquerade_disabled(zone):
    fw.removeMasquerade(zone)

def get_masquerade_enabled_permanent(zone):
    fw_zone = fw.config().getZoneByName(zone)
    fw_settings = fw_zone.getSettings()
    return fw_settings.getMasquerade()

def set_masquerade_enabled_permanent(zone):
    fw_zone = fw.config().getZoneByName(zone)
    fw_settings = fw_zone.getSettings()
    fw_settings.setMasquerade(True)
    fw_zone.update(fw_settings)

def set_masquerade_disabled_permanent(zone):
    fw_zone = fw.config().getZoneByName(zone)
    fw_settings = fw_zone.getSettings()
    fw_settings.setMasquerade(False)
    fw_zone.update(fw_settings)

####################
# interface handling
#
def get_interface_enabled(zone):
    if interface in fw.getInterfaces(zone):
        return True
    else:
        return False

def set_interface_enabled(zone):
    fw.addInterface(zone)

def set_interface_disabled(zone):
    fw.removeInterface(zone)

def get_interface_enabled_permanent(zone, interface):
    fw_zone = fw.config().getZoneByName(zone)
    fw_settings = fw_zone.getSettings()
    if interface in fw_settings.getInterfaces():
        return True
    else:
        return False

def set_interface_enabled_permanent(zone, interface):
    fw_zone = fw.config().getZoneByName(zone)
    fw_settings = fw_zone.getSettings()
    fw_settings.addInterface(interface)
    fw_zone.update(fw_settings)

def set_interface_disabled_permanent(zone, interface):
    fw_zone = fw.config().getZoneByName(zone)
    fw_settings = fw_zone.getSettings()
    fw_settings.removeInterface(interface)
    fw_zone.update(fw_settings)

def main():

    module = AnsibleModule(
        argument_spec = dict(
            service=dict(required=False,default=None),
            port=dict(required=False,default=None),
            rich_rule=dict(required=False,default=None),
            masquerade=dict(required=False,default=None),
            interface=dict(required=False,default=None),
            zone=dict(required=False,default=None),
            permanent=dict(type='bool',required=True),
            immediate=dict(type='bool',default=False),
            state=dict(choices=['enabled', 'disabled'], required=True),
            timeout=dict(type='int',required=False,default=0),
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

    if module.params['port'] != None:
        port, protocol = module.params['port'].split('/')
        if protocol == None:
            module.fail_json(msg='improper port format (missing protocol?)')
    else:
        port = None

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

    modification_count = 0
    if service != None:
        modification_count += 1
    if port != None:
        modification_count += 1
    if rich_rule != None:
        modification_count += 1
    if masquerade != None:
        modification_count += 1
    if interface != None:
        modification_count += 1

    if modification_count > 1:
        module.fail_json(msg='can only operate on port, service, rich_rule, masquerade or interface at once')

    if service != None:
        if permanent:
            is_enabled = get_service_enabled_permanent(zone, service)
            msgs.append('Permanent operation')

            if desired_state == "enabled":
                if is_enabled == False:
                    if module.check_mode:
                        module.exit_json(changed=True)

                    set_service_enabled_permanent(zone, service)
                    changed=True
            elif desired_state == "disabled":
                if is_enabled == True:
                    if module.check_mode:
                        module.exit_json(changed=True)

                    set_service_disabled_permanent(zone, service)
                    changed=True
        if immediate or not permanent:
            is_enabled = get_service_enabled(zone, service)
            msgs.append('Non-permanent operation')


            if desired_state == "enabled":
                if is_enabled == False:
                    if module.check_mode:
                        module.exit_json(changed=True)

                    set_service_enabled(zone, service, timeout)
                    changed=True
            elif desired_state == "disabled":
                if is_enabled == True:
                    if module.check_mode:
                        module.exit_json(changed=True)

                    set_service_disabled(zone, service)
                    changed=True

        if changed == True:
            msgs.append("Changed service %s to %s" % (service, desired_state))

    if port != None:
        if permanent:
            is_enabled = get_port_enabled_permanent(zone, [port, protocol])
            msgs.append('Permanent operation')

            if desired_state == "enabled":
                if is_enabled == False:
                    if module.check_mode:
                        module.exit_json(changed=True)

                    set_port_enabled_permanent(zone, port, protocol)
                    changed=True
            elif desired_state == "disabled":
                if is_enabled == True:
                    if module.check_mode:
                        module.exit_json(changed=True)

                    set_port_disabled_permanent(zone, port, protocol)
                    changed=True
        if immediate or not permanent:
            is_enabled = get_port_enabled(zone, [port,protocol])
            msgs.append('Non-permanent operation')

            if desired_state == "enabled":
                if is_enabled == False:
                    if module.check_mode:
                        module.exit_json(changed=True)

                    set_port_enabled(zone, port, protocol, timeout)
                    changed=True
            elif desired_state == "disabled":
                if is_enabled == True:
                    if module.check_mode:
                        module.exit_json(changed=True)

                    set_port_disabled(zone, port, protocol)
                    changed=True

        if changed == True:
            msgs.append("Changed port %s to %s" % ("%s/%s" % (port, protocol), \
                        desired_state))

    if rich_rule != None:
        if permanent:
            is_enabled = get_rich_rule_enabled_permanent(zone, rich_rule)
            msgs.append('Permanent operation')

            if desired_state == "enabled":
                if is_enabled == False:
                    if module.check_mode:
                        module.exit_json(changed=True)

                    set_rich_rule_enabled_permanent(zone, rich_rule)
                    changed=True
            elif desired_state == "disabled":
                if is_enabled == True:
                    if module.check_mode:
                        module.exit_json(changed=True)

                    set_rich_rule_disabled_permanent(zone, rich_rule)
                    changed=True
        if immediate or not permanent:
            is_enabled = get_rich_rule_enabled(zone, rich_rule)
            msgs.append('Non-permanent operation')

            if desired_state == "enabled":
                if is_enabled == False:
                    if module.check_mode:
                        module.exit_json(changed=True)

                    set_rich_rule_enabled(zone, rich_rule, timeout)
                    changed=True
            elif desired_state == "disabled":
                if is_enabled == True:
                    if module.check_mode:
                        module.exit_json(changed=True)

                    set_rich_rule_disabled(zone, rich_rule)
                    changed=True

        if changed == True:
            msgs.append("Changed rich_rule %s to %s" % (rich_rule, desired_state))

    if masquerade != None:
        if permanent:
            is_enabled = get_masquerade_enabled_permanent(zone)
            msgs.append('Permanent operation')

            if desired_state == "enabled":
                if is_enabled == False:
                    if module.check_mode:
                        module.exit_json(changed=True)

                    set_masquerade_enabled_permanent(zone)
                    changed=True
            elif desired_state == "disabled":
                if is_enabled == True:
                    if module.check_mode:
                        module.exit_json(changed=True)

                    set_masquerade_disabled_permanent(zone)
                    changed=True
        if immediate or not permanent:
            is_enabled = get_masquerade_enabled(zone)
            msgs.append('Non-permanent operation')

            if desired_state == "enabled":
                if is_enabled == False:
                    if module.check_mode:
                        module.exit_json(changed=True)

                    set_masquerade_enabled(zone)
                    changed=True
            elif desired_state == "disabled":
                if is_enabled == True:
                    if module.check_mode:
                        module.exit_json(changed=True)

                    set_masquerade_disabled(zone)
                    changed=True

        if changed == True:
            msgs.append("Changed masquerade to %s" % (desired_state))

    if interface != None:
        if permanent:
            is_enabled = get_interface_enabled_permanent(zone, interface)
            msgs.append('Permanent operation')

            if desired_state == "enabled":
                if is_enabled == False:
                    if module.check_mode:
                        module.exit_json(changed=True)

                    set_interface_enabled_permanent(zone, interface)
                    changed=True
            elif desired_state == "disabled":
                if is_enabled == True:
                    if module.check_mode:
                        module.exit_json(changed=True)

                    set_interface_disabled_permanent(zone, interface)
                    changed=True
        if immediate or not permanent:
            is_enabled = get_interface_enabled(zone, interface)
            msgs.append('Non-permanent operation')

            if desired_state == "enabled":
                if is_enabled == False:
                    if module.check_mode:
                        module.exit_json(changed=True)

                    set_interface_enabled(zone, interface)
                    changed=True
            elif desired_state == "disabled":
                if is_enabled == True:
                    if module.check_mode:
                        module.exit_json(changed=True)

                    set_interface_disabled(zone, interface)
                    changed=True

        if changed == True:
            msgs.append("Changed interface %s to %s" % (interface, desired_state))

    module.exit_json(changed=changed, msg=', '.join(msgs))

#################################################
# import module snippets
from ansible.module_utils.basic import *
main()
