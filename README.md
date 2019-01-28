# ifw (infrastructure firewall)
This tool expects a YAML file that represents the infrastructure. Based on this information fine grained firewall rules are generated for every system.

The firewall rules ensure the most restricted access for in- and output traffic. And uses iptables chains to store it iptables rules. 

Some assumption are made about the infrastructure:
 - Generated firewall rules can be stored in version management (git) and distributed with configuration management (Saltstack/Puppet/Ansible/...).
 - Only worry about INPUT/OUTPUT. More complex routing like FORWARDING can be done separately (ensure compatibility).
 - The location of the system is irrelevant.

IPv4 is still supported and this tool can be used to make migrating to IPv6 easier.

## Usage
python2.7 to_iptables.py --chain-name=INFRA --output-dir /output/dir --network-yaml network.yaml

## How to migrate
Migration is easy:
 1. Populate the YAML file with connections between systems (see network.yaml section).
 2. Use this tool to generate iptables rules for each system.
 3. Distribute and apply the iptables rules on the hosts (see deploy/.).
 4. ssh to a host and validate that the rule matches the expected traffic (iptables -nvL).
 5. Remove legacy rules from systems.
   
Bellow is the schema of the iptables INPUT chain:
```schema
 INPUT >--
         |
   +-----+------+  (Your own rules (optional))
   |CUSTOM CHAIN|  
   +-----+------+
         |
   +-----+-----+   (Generated with this tool, will
   |INFRA CHAIN|   only accept connection)
   +-----+-----+    
         |
   +-----+------+  (Your own or legacy iptables 
   |CUSTOM CHAIN|  rules (optional))
   +-----+------+
         |         (Also your own, could be:
   +-----+-----+   iptables -A INPUT -j LOG 
   |FINAL CHAIN|   iptables -A INPUT -j REJECT
   +-----------+   iptables -P INPUT -j DROP)
```

The INFRA chain is placed on top of your existing iptables rules and will only accept traffic that matches a rule. The same is done for the iptables OUTPUT chain. The policy of rejecting traffic is not handled by this tool. 

## network.yaml
See example\_network.yaml for the full examples code described bellow. The example will also include example code for:
 - Expose a webserver (many to one): Used to expose your services to the world. The keyword "world" is used as source in YAML to indicate to ignore the source (INPUT) and destination (OUTPUT) address when generating the firewall rules.
 - Access to ntp-services (one to many): Only used for exceptions like Network Time Protocol (NTP) if it is unknown what the designation IP ahead of time. You could host your own NPT-server and use the one-to-one method.
 - Group of systems (many to one): Can be used for a subnet of devices that you do not manage. A virtual node can be created to represent the subnet.

### Connecting systems (one to one)
```bash
python source/to_iptables.py --chain-name=INFRA --output-dir examples/example-01-out/ --network-yaml examples/example-01.yaml
```

#### nodes
```yaml
network:
  nodes:
    # one-to-one
    - name: laptop-01.example.com
      can_access:
        nodes:
          - name: admin-web-01.example.com
            services:
              - web 
        groups:
          - name: infra
            services:
              - dns
          - name: all
            services:
              - ssh
      exposes:
    # many-to-one: see virtual-public
    - name: admin-web-01.example.com
      can_access:
        nodes:
        groups:
          - name: infra
            services:
              - dns
      exposes:
        - web
```
#### Services
```yaml 
  services:
    - name: ssh
      rules:
        - name: ssh
          port: 22
          proto: tcp
    - name: dns
      rules:
        - name: dns
          port: 53
          proto: udp
    - name: web
      rules:
        - name: http
          port: 80
          proto: tcp
        - name: https
          port: 443
          proto: tcp
````
#### Nodedata
```yaml 
  nodedata:
    nodes:
      - name: laptop-01.example.com
        ipv4:
          - 1.2.3.4 
      - name: admin-web-01.example.com
        ipv4:
          - 1.2.3.5 
      - name: dns-01.example.com
        ipv4:
          - 1.2.3.7 
```

## Debugging
To unittest infra.py the following can be executed in the app directory:
```
python tests.py 
```

## Extending to other firewalls
To support a different firewall implementation you need to create your own to\_iptables.py file. infra.py is responsible for generating the firewall rules.

## Questions?
nick@aoeu-it.nl

## Final notes
In the walk-through above the YAML file is edited as static file. To use this in a scalable environment the YAML/JSON would be generated based on (dynamic) data sources. 

This tool is in the alpha stage, the following need to be implemented:
 - use selectors/labels instead of node groups.
 - use "spaces" to assign rules to interfaces.
 - (move to python 3.x)
