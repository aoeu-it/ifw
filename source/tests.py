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

import unittest
import yaml
from infra import infra

class TestYAMLMethods(unittest.TestCase):
    maxDiff = None

    def test_get_node(self):
        with open('tests/data.yaml') as fd:
            self.data = yaml.load(fd)
        dummy = self.data['unittests']['simple_network']['input']
        expected = self.data['unittests']['simple_network']['output_01']

        ret = infra.get_node('host-01.example.com', dummy['network'])

        self.assertEqual(expected[0], ret)

    def test_get_nodedata(self):
        with open('tests/data.yaml') as fd:
            self.data = yaml.load(fd)
        dummy = self.data['unittests']['simple_network']['input']
        expected = self.data['unittests']['simple_network']['output_02']

        ret = infra.get_nodedata('host-01.example.com', dummy['network'])

        self.assertEqual(sorted(expected[0]), sorted(ret))

    def test_get_nodes_from_group(self):
        with open('tests/data.yaml') as fd:
            self.data = yaml.load(fd)
        dummy = self.data['unittests']['simple_network']['input']
        expected = self.data['unittests']['simple_network']['output_03']

        ret = infra.get_nodes_from_group('group1', dummy['network'])

        self.assertEqual(expected, ret)

    def test_get_egress_services(self):
        with open('tests/data.yaml') as fd:
            self.data = yaml.load(fd)
        dummy = self.data['unittests']['simple_network']['input']
        node = self.data['unittests']['simple_network']['input']['network']['nodes'][0]
        expected = self.data['unittests']['simple_network']['output_04']

        ret = infra.get_egress_services(node, dummy['network'])

        self.assertEqual(sorted(expected), sorted(ret))

    def test_get_egress_nodes(self):
        with open('tests/data.yaml') as fd:
            self.data = yaml.load(fd)
        dummy = self.data['unittests']['simple_network']['input']
        node = self.data['unittests']['simple_network']['input']['network']['nodes'][0]
        expected = self.data['unittests']['simple_network']['output_05']

        ret = infra.get_egress_nodes(node, dummy['network'])

        self.assertEqual(sorted(expected), sorted(ret))

    def test_get_ingress_nodes(self):
        with open('tests/data.yaml') as fd:
            self.data = yaml.load(fd)
        dummy = self.data['unittests']['simple_network']['input']
        expected = self.data['unittests']['simple_network']['output_06']

        ret = infra.get_ingress_nodes('host-01.example.com', dummy['network'])

        self.assertEqual(sorted(expected), ret)

    def test_create_ingress_rules(self):
        with open('tests/data.yaml') as fd:
            self.data = yaml.load(fd)
        dummy = self.data['unittests']['simple_network']['input']
        expected = self.data['unittests']['simple_network']['output_07']

        ret = infra.create_ingress_rules('host-01.example.com', dummy['network'])

        self.assertEqual(sorted(expected), sorted(ret['ipv6']))

    def test_create_egress_rules(self):
        with open('tests/data.yaml') as fd:
            self.data = yaml.load(fd)
        dummy = self.data['unittests']['simple_network']['input']
        expected = self.data['unittests']['simple_network']['output_08']

        ret = infra.create_egress_rules('host-01.example.com', dummy['network'])

        self.assertEqual(sorted(expected), sorted(ret['ipv6']))

    def test_can_access(self):
        with open('tests/data.yaml') as fd:
            self.data = yaml.load(fd)
        dummy = self.data['unittests']['simple_network']['input']

        ret = infra.can_access('host-01.example.com', 'app1', dummy['network'])
        self.assertEqual(True, ret)

        ret = infra.can_access('host-01.example.com', 'app2', dummy['network'])
        self.assertEqual(False, ret)

if __name__ == '__main__':
    unittest.main()
