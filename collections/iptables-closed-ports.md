## Closed port probing collection for iptables

A collection to detect probing on closed ports.

This is a little different to the crowdsec iptables-port-scanner as this does not require the ports to be unique, if someone tries port 22 three times it's an attacker.

There are 2 secnarios, 1 for TCP which overflows at 3 and 1 for UDP which overflows at 10.

Iptables is set to log all (NEW) traffic to closed ports.

