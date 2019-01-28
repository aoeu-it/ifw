#!/usr//bin/env python

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

import yaml
import string

from optparse import OptionParser
from infra import infra

class to_iptables(object):
    """
    Translate a datastructure to iptables rules. The data will be a
    list with following structure:

  - name: host-06.example.com
    egress:
      ipv4: []
      ipv6:
      - {description: access to 1/tcp on host-06.example.com, destination: '2001:db8::',
        name: rule1, port: 1, proto: tcp}
    ingress:
      ipv4: []
      ipv6:
      - {description: host-06.example.com has access on 1/tcp, name: rule1, port: 1,
        proto: tcp, source: '2001:db8::'}

    """
    @staticmethod
    def create_fw_rules(network, out_directory, chain):
        """
        Implement this method to produce a firewall rule.
        ip: destination ip with or without subnet suffix.
        """
        chain = chain.upper()

        for node in network:
            r = list()
            # Create the egress and ingress rules.
            r += to_iptables.create_fw_egress_rules(node, chain)
            r += to_iptables.create_fw_ingress_rules(node, chain)

            # Write the iptables rules to "nodename".
            with open(out_directory+'/'+node['name']+'-'+chain+'.rules', 'w') as fd:
                # Write the iptables rules to "nodename".
                fd.write('iptables -N IN_'+str(chain)+"\n")
                fd.write('iptables -I INPUT -j IN_'+str(chain)+"\n")
                fd.write('iptables -I IN_'+str(chain)+" -m state --state ESTABLISHED -j ACCEPT\n")

                fd.write('iptables -N OUT_'+str(chain)+"\n")
                fd.write('iptables -I OUTPUT -j OUT_'+str(chain)+"\n")
                fd.write('iptables -I OUT_'+str(chain)+" -m state --state ESTABLISHED -j ACCEPT\n")

                for i in r:
                    fd.write(i+"\n")

    @staticmethod
    def create_fw_egress_rules(node, chain):
        """
        Translate the datastructure to iptables commands.
        """
        r = list()

        for ip_family in ['ipv4', 'ipv6']:
            for rule in node['egress'][ip_family]:
                # Basic rule template for egress.
                rule_template = [['-p', 'proto'], ['-s', 'source'], ['-d', 'destination'], ['--dport', 'port']]

                iptables_rule = list()
                iptables_rule.append(['-I', 'OUT_'+str(chain)])

                # Check if key is present in rule. Could be removed by keyword.
                for key in rule_template:
                    if key[1] in rule:
                        iptables_rule.append([key[0], rule[key[1]]])

                iptables_rule.append(['--sport', '1025:65535'])
                iptables_rule.append(['-m', 'comment'])
                iptables_rule.append(['--comment', '"iptables-exporter: '+str(rule['description']+'"')])
                iptables_rule.append(['-j', 'ACCEPT'])

                if ip_family is 'ipv4':
                    # Generate iptables rules and save in r list.
                    r.append('iptables '+string.join([str(item[0])+' '+str(item[1]) for item in iptables_rule]))
                else:
                    r.append('ip6tables '+string.join([str(item[0])+' '+str(item[1]) for item in iptables_rule]))

        return r

    @staticmethod
    def create_fw_ingress_rules(node, chain):
        """
        Translate the datastructure to iptables commands.
        """
        r = list()

        for ip_family in ['ipv4', 'ipv6']:
            for rule in node['ingress'][ip_family]:
                # Basic rule template for egress.
                rule_template = [['-p', 'proto'], ['-s', 'source'], ['-d', 'destination'], ['--dport', 'port']]

                iptables_rule = list()
                iptables_rule.append(['-I', 'IN_'+str(chain)])

                # Check if key is present in rule. Could be removed by keyword.
                for key in rule_template:
                    if key[1] in rule:
                        iptables_rule.append([key[0], rule[key[1]]])

                iptables_rule.append(['--sport', '1025:65535'])
                iptables_rule.append(['-m', 'comment'])
                iptables_rule.append(['--comment', '"iptables-exporter: '+str(rule['description']+'"')])
                iptables_rule.append(['-j', 'ACCEPT'])


                if ip_family is 'ipv4':
                    # Generate iptables rules and save in r list.
                    r.append('iptables '+string.join([str(item[0])+' '+str(item[1]) for item in iptables_rule]))
                else:
                    r.append('ip6tables '+string.join([str(item[0])+' '+str(item[1]) for item in iptables_rule]))

        return r


if '__main__' == __name__:
    parser = OptionParser()
    parser.add_option("--chain-name", dest="chain_name", help="chain name that will be used in iptables.", default="INFRA")
    parser.add_option("--network-yaml", dest="network_yaml", help="yaml file representing the network.")
    parser.add_option("--output-dir", dest="output_dir", help="files containing iptables will be placed in this directory.")

    (options, args) = parser.parse_args()

    with open(options.network_yaml) as fd:
        data = yaml.load(fd)
        network = infra.generate_rules(data['network'])

        to_iptables.create_fw_rules(network, options.output_dir, options.chain_name)
