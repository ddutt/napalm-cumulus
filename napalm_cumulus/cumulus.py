# Copyright 2016 Dravetech AB. All rights reserved.
#
# The contents of this file are licensed under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with the
# License. You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations under
# the License.

"""
Napalm driver for Cumulus.

Read https://napalm.readthedocs.io for more information.
"""

from __future__ import print_function
from __future__ import unicode_literals

import re
import json
import ipaddress
from datetime import datetime
from pytz import timezone
from collections import defaultdict

import requests
from requests.auth import HTTPBasicAuth
import urllib3

from netmiko import ConnectHandler
from netmiko.ssh_exception import NetMikoTimeoutException
import napalm_base.constants as C
from napalm.base.helpers import mac
from napalm.base.utils import py23_compat
from napalm.base.utils import string_parsers
from napalm.base.base import NetworkDriver
from napalm.base.exceptions import (
    ConnectionException,
    MergeConfigException,
    CommandErrorException,
    SessionLockedException
    )


class CumulusDriver(NetworkDriver):
    """Napalm driver for Cumulus."""

    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        """Constructor."""
        self.device = None
        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout
        self.loaded = False
        self.changed = False

        if optional_args is None:
            optional_args = {}

        self.transport = optional_args.get('transport', 'https')

        if self.transport == 'https':

            self.port = optional_args.get('port', 8080)
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        # We need both HTTP  and SSH since not all commands are exposed via
        # the REST API. There is no support for different user name and passwd
        # between the REST API and ssh.

        # Netmiko possible arguments
        netmiko_argument_map = {
            'port': None,
            'verbose': False,
            'global_delay_factor': 1,
            'use_keys': False,
            'key_file': None,
            'ssh_strict': False,
            'system_host_keys': False,
            'alt_host_keys': False,
            'alt_key_file': '',
            'ssh_config_file': None,
            'secret': None,
            'allow_agent': False
        }

        # Build dict of any optional Netmiko args
        self.netmiko_optional_args = {
            k: optional_args.get(k, v)
            for k, v in netmiko_argument_map.items()
        }
        self.port = optional_args.get('port', 22)
        self.sudo_pwd = optional_args.get('sudo_pwd', self.password)

    def _exec_command(self, cmd, decode_json=False, transport='https'):
        """Execute the command remotely depending on the transport"""

        out = None

        if self.transport == 'https' and transport == 'https':
            words = cmd.split()
            if not words:
                return out        # Ignore blank lines
            if words[0] == 'net':
                cmd = words[1:]

            data = {"cmd": cmd}
            headers = {'Content-Type': 'application/json'}

            r = requests.post(
                'https://{}:8080/nclu/v1/rpc'.format(self.hostname),
                data=json.dumps(data), headers=headers,
                auth=HTTPBasicAuth(self.username, self.password),
                verify=False)

            if r.status_code == requests.status_codes.codes.ALL_OK:
                if decode_json:
                    try:
                        out = json.loads(r.text)
                    except ValueError:
                        out = {'error': r.text}
                else:
                    out = r.text
        else:
            out = self._send_command(cmd)

        return out

    def open(self):
        try:
            if self.transport == 'https':
                if not self._exec_command('show version'):
                    raise ConnectionException('Cannot reach REST API.')

            self.device = ConnectHandler(device_type='linux',
                                         host=self.hostname,
                                         username=self.username,
                                         password=self.password,
                                         **self.netmiko_optional_args)
            # Enter root mode.
            if self.netmiko_optional_args.get('secret'):
                self.device.enable()
        except NetMikoTimeoutException:
            raise ConnectionException('Cannot connect to {}'.format(self.hostname))
        except ValueError:
            raise ConnectionException('Cannot become root.')

    def close(self):
        self.device.disconnect()

    def is_alive(self):
        return {
            'is_alive': self.device.remote_conn.transport.is_active()
        }

    def _load_config(self, filename, config, replace=False):
        '''The workhorse routine to load config & possibly replace'''
        if not filename and not config:
            raise MergeConfigException('filename or config param must be provided.')

        self.loaded = True

        if filename is not None:
            with open(filename, 'r') as f:
                candidate = f.readlines()
        else:
            candidate = config

        if not isinstance(candidate, list):
            candidate = [candidate]

        candidate = [line for line in candidate if line]
        if replace:
            candidate.insert(0, 'del all')  # Delete existing configuration

        for command in candidate:
            output = self._exec_command(command)
            if output is not None and (
                    "error" in output or "not found" in output):
                raise MergeConfigException("Command '{0}' cannot be applied." \
                                           .format(command))

    def load_merge_candidate(self, filename=None, config=None):
        '''Merge existing config with new config'''
        self._load_config(filename, config, False)

    def load_replace_candidate(self, filename=None, config=None):
        '''Replace existing config with the one provided'''
        self._load_config(filename, config, True)

    def discard_config(self):
        if self.loaded:
            self._exec_command('abort')
            self.loaded = False

    def compare_config(self):
        if self.loaded:
            diff = self._exec_command('pending')
            return diff
        return ''

    def commit_config(self, force=False):
        if self.loaded:
            pending_cmds = self.compare_config()
            if ('NOTE: Multiple users are currently staging changes' in
                pending_cmds and not force):
                raise SessionLockedException(
                    'ERROR: Multiple users are currently staging changes')
            self._exec_command('commit')
            self.changed = True
            self.loaded = False

    def rollback(self):
        if self.changed:
            self._exec_command('rollback last')
            self.changed = False

    def _send_command(self, command):
        words = command.split()

        if words[0] == 'sudo':
            words.insert(1, '-S <<< "' +  self.sudo_pwd + '" ')
            command = ' '.join(words)
        response = self.device.send_command(command)
        return response

    def get_facts(self):
        facts = {
            'vendor': py23_compat.text_type('Cumulus')
        }

        # Get "net show hostname" output.
        hostname = self._exec_command('show hostname')

        # Get "net show system" output.
        show_system_output = self._exec_command('show system')
        for i, line in enumerate(show_system_output.splitlines()):
            if i == 0:
                model = line.strip()
            elif 'build' in line.lower():
                os_version = line.split()[-1]
            elif 'uptime' in line.lower():
                uptime = line.split()[-1]

        # Get "decode-syseeprom" output.
        serial_number = self._exec_command('decode-syseeprom -e',
                                                         transport='ssh')
        # Get "net show interface all json" output.
        interfaces = json.loads(self._exec_command('show interface all json'))

        facts['hostname'] = facts['fqdn'] = py23_compat.text_type(hostname)
        facts['os_version'] = py23_compat.text_type(os_version)
        facts['model'] = py23_compat.text_type(model)
        facts['uptime'] = string_parsers.convert_uptime_string_seconds(uptime)
        facts['serial_number'] = py23_compat.text_type(serial_number)
        facts['interface_list'] = string_parsers.sorted_nicely(interfaces.keys())
        return facts

    def cli(self, commands):
        cli_output = {}

        if type(commands) is not list:
            raise TypeError('Please provide a valid LIST of commands!')

        for command in commands:
            try:
                cli_output[py23_compat.text_type(command)] = self._send_command(command)
                # not quite fair to not exploit rum_commands
                # but at least can have better control to point to wrong command in case of failure
            except Exception as e:
                # something bad happened
                msg = 'Unable to execute command "{cmd}": {err}'.format(cmd=command, err=e)
                cli_output[py23_compat.text_type(command)] = msg
                raise CommandErrorException(str(cli_output))

        return cli_output


    def get_mac_address_table(self):

        mac_table = []

        mac_entries = self._exec_command('show bridge macs json',
                                         decode_json=True)

        for mac_entry in mac_entries:
            vlan = mac_entry.get('vlan')
            interface = mac_entry.get('dev')
            mac_raw = mac_entry.get('mac')
            static = any(n in mac_entry.get('flags', [])
                         for n in ['static', 'self'])
            remote = ('offload' in mac_entry.get('flags', []))
            last_move = mac_entry.get('updated', 0.0)
            moves = -1
            mac_table.append(
                {
                    'mac': mac(mac_raw),
                    'interface': interface,
                    'vlan': vlan,
                    'active': True,
                    'static': static,
                    'remote': remote,
                    'moves': moves,
                    'last_move': last_move
                }
            )

        return mac_table

    def get_arp_table(self):

        """
        'show arp' output example:
        Address                  HWtype  HWaddress           Flags Mask            Iface
        10.129.2.254             ether   00:50:56:97:af:b1   C                     eth0
        192.168.1.134                    (incomplete)                              eth1
        192.168.1.1              ether   00:50:56:ba:26:7f   C                     eth1
        10.129.2.97              ether   00:50:56:9f:64:09   C                     eth0
        192.168.1.3              ether   00:50:56:86:7b:06   C                     eth1
        """
        output = self._exec_command('arp -n', transport='ssh')
        output = output.split("\n")
        output = output[1:]
        arp_table = list()

        for line in output:
            line = line.split()
            if "incomplete" in line[1]:
                macaddr = py23_compat.text_type("00:00:00:00:00:00")
            else:
                macaddr = py23_compat.text_type(line[2])

            arp_table.append(
                {
                    'interface': py23_compat.text_type(line[-1]),
                    'mac': macaddr,
                    'ip': py23_compat.text_type(line[0]),
                    'age': 0.0
                }
            )
        return arp_table

    def get_ntp_stats(self):
        """
        'ntpq -np' output example
             remote           refid      st t when poll reach   delay   offset  jitter
        ==============================================================================
         116.91.118.97   133.243.238.244  2 u   51   64  377    5.436  987971. 1694.82
         219.117.210.137 .GPS.            1 u   17   64  377   17.586  988068. 1652.00
         133.130.120.204 133.243.238.164  2 u   46   64  377    7.717  987996. 1669.77
        """

        output = self._exec_command("show time ntp servers")
        output = output.split("\n")[2:]
        ntp_stats = []

        for ntp_info in output:
            ntp_info_array = ntp_info.split()

            if len(ntp_info_array) == 10:
                remote, refid, st, t, when, hostpoll, reachability, delay, \
                    offset, jitter = ntp_info_array
            elif len(ntp_info_array) == 11:
                # sometimes you get remote entries like: "+66.96.98.9 (66-".
                # The first two entries of the split are still remote
                remote = ' '.join(ntp_info_array[0:1])
                refid, st, t, when, hostpoll, reachability, delay, offset, \
                    jitter = ntp_info_array[2:]
            else:
                continue

            # 'remote' contains '*' if the machine synchronized with NTP server
            synchronized = "*" in remote

            match = re.search("^[*+-](.*)", remote)
            if match:
                ip = match.group(1)
            else:
                ip = remote

            when = when if when != '-' else 0

            ntp_stats.append({
                "remote": py23_compat.text_type(ip),
                "referenceid": py23_compat.text_type(refid),
                "synchronized": bool(synchronized),
                "stratum": int(st),
                "type": py23_compat.text_type(t),
                "when": py23_compat.text_type(when),
                "hostpoll": int(hostpoll),
                "reachability": int(reachability),
                "delay": float(delay),
                "offset": float(offset),
                "jitter": float(jitter)
            })

        return ntp_stats

    def ping(self,
             destination,
             source=C.PING_SOURCE,
             ttl=C.PING_TTL,
             timeout=C.PING_TIMEOUT,
             size=C.PING_SIZE,
             count=C.PING_COUNT,
             vrf=C.PING_VRF):

        deadline = timeout * count

        command = "ping %s -i 0.2 " % destination
        command += "-t %d " % int(ttl)
        command += "-w %d " % int(deadline)
        command += "-s %d " % int(size)
        command += "-c %d " % int(count)
        if source != "":
            command += "interface %s " % source

        ping_result = dict()
        output_ping = self._exec_command(command, transport='ssh')

        if "Unknown host" in output_ping:
            err = "Unknown host"
        else:
            err = ""

        if err is not "":
            ping_result["error"] = err
        else:
            # 'packet_info' example:
            # ['5', 'packets', 'transmitted,' '5', 'received,' '0%', 'packet',
            # 'loss,', 'time', '3997ms']
            packet_info = output_ping.split("\n")

            if ('transmitted' in packet_info[-2]):
                packet_info = packet_info[-2]
            else:
                packet_info = packet_info[-3]

            packet_info = [x.strip() for x in packet_info.split()]

            sent = int(packet_info[0])
            received = int(packet_info[3])
            lost = sent - received

            # 'rtt_info' example:
            # ["0.307/0.396/0.480/0.061"]
            rtt_info = output_ping.split("\n")

            if len(rtt_info[-1]) > 0:
                rtt_info = rtt_info[-1]
            else:
                rtt_info = rtt_info[-2]

            match = re.search("([\d\.]+)/([\d\.]+)/([\d\.]+)/([\d\.]+)", rtt_info)

            if match is not None:
                rtt_min = float(match.group(1))
                rtt_avg = float(match.group(2))
                rtt_max = float(match.group(3))
                rtt_stddev = float(match.group(4))
            else:
                rtt_min = None
                rtt_avg = None
                rtt_max = None
                rtt_stddev = None

            ping_responses = list()
            response_info = output_ping.split("\n")

            for res in response_info:
                match_res = re.search("from\s([\d\.]+).*time=([\d\.]+)", res)
                if match_res is not None:
                    ping_responses.append(
                      {
                        "ip_address": match_res.group(1),
                        "rtt": float(match_res.group(2))
                      }
                    )

            ping_result["success"] = dict()

            ping_result["success"] = {
                "probes_sent": sent,
                "packet_loss": lost,
                "rtt_min": rtt_min,
                "rtt_max": rtt_max,
                "rtt_avg": rtt_avg,
                "rtt_stddev": rtt_stddev,
                "results": ping_responses
            }

            return ping_result

    def _get_interface_neighbors(self, neighbors_list):
        neighbors = []
        for i, nbr in enumerate(neighbors_list['chassis'][0]['name']):
            temp = {}
            temp['hostname'] = nbr['value']
            temp['port'] = neighbors_list['port'][0]['id'][i]['value']
            neighbors.append(temp)
        return neighbors

    def get_lldp_neighbors(self):
        """Cumulus get_lldp_neighbors."""
        lldp = {}
        command = 'show lldp json'

        lldp_output = json.loads(self._exec_command(command))['lldp'][0]['interface']

        for interface in lldp_output:
            lldp[interface['name']] = self._get_interface_neighbors(interface)
        return lldp

    def get_interfaces(self):

        interfaces = {}
        # Get 'net show interface all json' output.

        output = self._exec_command('show interface all json')
        # Handling bad send_command_timing return output.
        output_json = json.loads(output)

        for interface in output_json:
            interfaces[interface] = {}
            if output_json[interface]['linkstate'] == "ADMDN":
                interfaces[interface]['is_enabled'] = False
            else:
                interfaces[interface]['is_enabled'] = True

            if output_json[interface]['linkstate'] == "UP":
                interfaces[interface]['is_up'] = True
            else:
                interfaces[interface]['is_up'] = False

            interfaces[interface]['description'] = py23_compat.text_type(
                                            output_json[interface]['iface_obj']['description'])

            if output_json[interface]['speed'] is None:
                interfaces[interface]['speed'] = -1
            else:
                interfaces[interface]['speed'] = output_json[interface]['speed']

            interfaces[interface]['mac_address'] = py23_compat.text_type(
                                            output_json[interface]['iface_obj']['mac'])

        # Test if the FRR daemon is running.
        frr_test = self._exec_command('systemctl status frr', transport='ssh')
        frr_status = False

        for line in frr_test.splitlines():
            if 'Active:' in line:
                status = line.split()[1]
                if 'inactive' in status:
                    frr_status = False
                elif 'active' in status:
                    frr_status = True
                else:
                    frr_status = False

        # If the FRR daemon is running for each interface run the show interface command
        # to get information about the most recent interface change.
        if frr_status:
            for interface in interfaces.keys():
                command = "vtysh -c 'show interface %s'" % interface
                quagga_show_int_output = self._exec_command(command, transport='ssh')
                # Get the link up and link down datetimes if available.
                last_flapped_1 = last_flapped_2 = False
                for line in quagga_show_int_output.splitlines():
                    if 'Link ups' in line:
                        if '(never)' in line.split()[4]:
                            last_flapped_1 = False
                        else:
                            last_flapped_1 = True
                            last_flapped_1_date = line.split()[4] + " " + line.split()[5]
                            last_flapped_1_date = datetime.strptime(
                                                last_flapped_1_date, "%Y/%m/%d %H:%M:%S.%f")
                    if 'Link downs' in line:
                        if '(never)' in line.split()[4]:
                            last_flapped_2 = False
                        else:
                            last_flapped_2 == True
                            last_flapped_2_date = line.split()[4] + " " + line.split()[5]
                            last_flapped_2_date = datetime.strptime(
                                                last_flapped_2_date, "%Y/%m/%d %H:%M:%S.%f")
                # Compare the link up and link down datetimes to determine the most recent and
                # set that as the last flapped after converting to seconds.
                if last_flapped_1 and last_flapped_2:
                    last_delta = last_flapped_1_date - last_flapped_2_date
                    if last_delta.days >= 0:
                        last_flapped = last_flapped_1_date
                    else:
                        last_flapped = last_flapped_2_date
                elif last_flapped_1:
                    last_flapped = last_flapped_1_date
                elif last_flapped_2:
                    last_flapped = last_flapped_2_date
                else:
                    last_flapped = -1

                if last_flapped != -1:
                    # Get remote timezone.
                    tmz = self._exec_command('date +"%Z"')
                    now_time = datetime.now(timezone(tmz))
                    last_flapped = last_flapped.replace(tzinfo=timezone(tmz))
                    last_flapped = (now_time - last_flapped).total_seconds()
                interfaces[interface]['last_flapped'] = float(last_flapped)

        # If FRR daemon isn't running set all last_flapped values to -1.
        else:
            for interface in interfaces.keys():
                interfaces[interface]['last_flapped'] = -1

        return interfaces

    def get_interfaces_counters(self):
        '''Get the dump from /proc/net/dev as its the most accurate'''

        # net show counters shows packets, not bytes
        output = self._exec_command('cat /proc/net/dev',
                                    transport='ssh').splitlines()
        interface_counters = {}

        output = output[2:]
        for line in output:
            words = line.split()
            interface = words[0].split(':')[0]
            interface_counters[interface] = {}
            interface_counters[interface].update(
                tx_octets=words[1],
                rx_octets=words[9],
                tx_unicast_packets=-1,
                rx_unicast_packets=-1,
                tx_multicast_packets=words[8],
                rx_multicast_packets=-1,
                tx_broadcast_packets=-1,
                rx_broadcast_packets=-1,
                tx_discards=words[4],
                rx_discards=words[12],
                tx_errors=words[3],
                rx_errors=words[11]
            )
        return interface_counters

    def get_interfaces_ip(self):
        # Get net show interface all json output.
        output = self._exec_command('show interface all json')
        # Handling bad send_command_timing return output.
        try:
            output_json = json.loads(output)
        except ValueError:
            output_json = json.loads(self._exec_command('show interface all json'))

        interfaces_ip = {}

        for interface in output_json:
            if interface not in interfaces_ip:
                interfaces_ip[interface] = {}

            if output_json[interface]['iface_obj']['ip_address'].get('allentries', None):
                for ip_address in output_json[interface]['iface_obj']['ip_address']['allentries']:
                    ip_ver = ipaddress.ip_interface(py23_compat.text_type(ip_address)).version
                    ip_ver = 'ipv{}'.format(ip_ver)
                    if ip_ver not in interfaces_ip[interface]:
                        interfaces_ip[interface][ip_ver] = {}
                    ip, prefix = ip_address.split('/')
                    interfaces_ip[interface][ip_ver][ip] = {'prefix_length': int(prefix)}

        return interfaces_ip
