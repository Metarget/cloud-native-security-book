#!/bin/bash

set -e -x

kubectl delete pod victim attacker

for record in $(arp  | grep cni0 | awk '{print $1}'); do
  arp -d "$record"
done
