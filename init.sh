#!/bin/bash

pod_cidr=10.240.0.0/24

#   Allow pod to pod communication
iptables -A FORWARD -s $pod_cidr -j ACCEPT 
iptables -A FORWARD -d $pod_cidr -j ACCEPT

#   Allow communication across hosts
#   Uncomment the following lines and replace <other-node-1-pod-cidr> and 
#   <other-node-1-ip> with the pod cidr and ip of the other node(s)
# ip route add <other-node-1-pod-cidr>/24 via <other-node-1-ip> dev eth0
# ...

#   Allow outgoing internet 
iptables -t nat -A POSTROUTING -s $pod_cidr ! -o cni0 -j MASQUERADE

