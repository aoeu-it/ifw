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
import copy

class infra(object):
    """
    The purpose of this class is to create a object containing nodes
    and the associated firewall rules.
    """
    @staticmethod
    def process_keywords_in_rule(rules):
        """
        Modify template based on keywords.
        For example, destination = 'world', will ensure to communicate without destination ip restriction.
        """
        # modification rules:
        mods = [{'keyword': 'world', 'key': 'destination', 'action': 'delete'},
                {'keyword': 'world', 'key': 'source', 'action': 'delete'}]

        for ip_family in rules.keys():
            for rule in rules[ip_family]:
                for mod in mods:
                    if mod['action'] is 'delete':
                        # remove key from rule template:
                        if rule[mod['key']] == mod['keyword']:
                            rule.pop(mod['key'])

        return rules

    @staticmethod
    def generate_rules(network):
        s = list()
        for node in network['nodes']:
            e = infra.process_keywords_in_rule(infra.create_egress_rules(node['name'], network))
            i = infra.process_keywords_in_rule(infra.create_ingress_rules(node['name'], network))
            s.append({'name': node['name'], 'ingress': i, 'egress': e})

        return s

    @staticmethod
    def create_egress_rules(nodeid, network, limit_to_nodeid=None):
        """
        Gather information to be able to create a firewall rule.
        """
        rules = {'ipv4': list(), 'ipv6': list()}
        node = infra.get_node(nodeid, network)
        nodedata = infra.get_nodedata(nodeid, network)
        other_nodes = infra.get_egress_nodes(node, network)

        # Limit the egress nodes to only one node.
        # Purpose: This will save redundant code in create_ingress_rules() method.
        if limit_to_nodeid is not None:
            other_nodes = [infra.get_node(limit_to_nodeid, network)]

        for other_node in other_nodes:
            other_nodedata = infra.get_nodedata(other_node['name'], network)

            # Create a list of services...
            services = list()
            for s in infra.get_egress_services(node, network):
                if s['name'] == other_node['name']:
                    services += s['services']

            # Which services want node to access on other_node?
            for service_name in services:
                # Does other node exposes this service?
                if infra.can_access(other_node['name'], service_name, network):
                    service = infra.get_service(service_name, network)

                    # What kind of ip family is supported by egress node?
                    egress_ip_families = [i for i in ['ipv4', 'ipv6'] if i in other_nodedata]
                    for egress_ip_family in egress_ip_families:
                        # Is ip family supported in current node?
                        if egress_ip_family in nodedata:
                            # Ready to assemble firewall rule.
                            for node_ip in nodedata[egress_ip_family]:
                                for egress_ip in other_nodedata[egress_ip_family]:
                                    for rule in service['rules']:
                                        # Can this be accomplish by making "network" immutable?
                                        rule = copy.copy(rule)
                                        rule.update({'source': node_ip})
                                        rule.update({'destination': egress_ip})
                                        rule.update({'sport': '1025:65535'})
                                        rule.update({'description': 'access to '+str(rule['port'])+'/'+rule['proto']+' on '+other_node['name']})
                                        rules[egress_ip_family].append(rule)

        return rules

    @staticmethod
    def create_ingress_rules(nodeid, network):
        """
        A symmetry exists between ingress and egress rules. So:
         1. generate egress rules for all the ingres nodes.
         2. get only the egress rules that apply for this node.
         3. convert egress rules to ingress rules:
          - swap value between source and destination (is done automatically
            by using ingress node as argument of create_egress_rules()).
          - generate new description.
        """
        ingress_nodes = infra.get_ingress_nodes(nodeid, network)
        ingress_rules = {'ipv4': [], 'ipv6': []}

        for ingress_node in ingress_nodes:
            # Step 1 and 2.
            rules = infra.create_egress_rules(ingress_node['name'], network, limit_to_nodeid=nodeid)
            # Step 3: convert egress to ingress rules.
            for ip_family in rules.keys():
                for rule in rules[ip_family]:
                    # Create new description
                    rule.update({'description': 'allow '+str(ingress_node['name'])+' on '+str(rule['port'])+'/'+rule['proto']})
                    rule.update({'dport': '1025:65535'})
                    rule.pop('sport')

                    ingress_rules[ip_family].append(rule)

        return ingress_rules

    @staticmethod
    def can_access(nodeid, service_name, network):
        """
        Does a node with nodeid exposes service_name?
        """
        node = infra.get_node(nodeid, network)
        if 'exposes' in node:
            if node['exposes'] is not None:
                if service_name in node['exposes']:
                    return True

        return False

    @staticmethod
    def get_service(service_name, network):
        try:
            return infra._get_item_by_name(service_name, network['services'])
        except Exception:
            raise Exception('missing item with name "'+service_name+'" in services.')

    @staticmethod
    def get_nodedata(nodeid, network):
        try:
            return infra._get_item_by_name(nodeid, network['nodedata']['nodes'])
        except Exception:
            raise Exception('missing item with name "'+nodeid+'" in nodedata.')

    @staticmethod
    def _get_item_by_name(name, data):
        for item in data:
            if item['name'] == name:
                return item

        raise Exception()

    @staticmethod
    def get_ingress_nodes(nodeid, network):
        """
        Which nodes want to access this node?

        nodeid: the node id (string)
        network: a dictionary representing the network (dictionary)
        """
        # Get nodes that want to access the current node.
        c = list()
        for other_node in network['nodes']:
            node_bucket = infra.get_egress_nodes(other_node, network)

            # Check which node in bucket wants to access a node with node_id.
            for n in node_bucket:
                if nodeid == n['name']:
                    c.append(other_node)

        return sorted(c)

    @staticmethod
    def get_egress_nodes(node, network):
        """
        Which nodes does node wants to access?
        """
        node_bucket = list()
        # Create a bucket with nodes associated with "other_node".
        # Associated by group.
        if node['can_access']['groups'] is not None:
            for g in node['can_access']['groups']:
                node_bucket += infra.get_nodes_from_group(g['name'], network)

        # Associated by nodeid.
        if node['can_access']['nodes'] is not None:
            for n in node['can_access']['nodes']:
                n = infra.get_node(n['name'], network)
                if n is not None:
                    node_bucket.append(n)

        return node_bucket

    # FIXME: naming of method should be more clear.
    @staticmethod
    def get_egress_services(node, network):
        """
        Which services want node to access on each node?

        Will return in format:
        - name: nodeN
          services:
            - app1
            - app2
        - ...
        """
        node_bucket = list()

        # Expand group to node list with services.
        if node['can_access']['groups'] is not None:
            for g in node['can_access']['groups']:
                nodes = infra.get_nodes_from_group(g['name'], network)
                for n in nodes:
                    if 'services' in g:
                        node_bucket.append({'name': n['name'], 'services': g['services']})

        # Associated by nodeid.
        if node['can_access']['nodes'] is not None:
            for n in node['can_access']['nodes']:
                if 'services' in n:
                    node_bucket.append(n)

        return node_bucket

    @staticmethod
    def get_nodes_from_group(groupname, network):
        """
        Return a list of nodes that are in a specific group.
        """
        s = list()
        for g in network['groups']:
            if g['name'] == groupname:
                for nodeid in g['nodes']:
                    n = infra.get_node(nodeid, network)
                    if n is not None:
                        s.append(n)

        return s

    @staticmethod
    def get_node(nodeid, network):
        for node in network['nodes']:
            if nodeid == node['name']:
                return node

        return None

if '__main__' == __name__:
    with open('tests/data.yaml') as fd:
        data = yaml.load(fd)
        rules = infra.generate_rules(data['unittests']['simple_network']['input']['network'])
