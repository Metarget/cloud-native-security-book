#!/bin/bash

set -e -x

rm -f /usr/bin/kata*
rm -r /etc/kata-containers
rm -r /opt/kata
rm /etc/docker/daemon.json
rm /etc/systemd/system/docker.service.d/kata-containers.conf

systemctl daemon-reload && systemctl restart docker