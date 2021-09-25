#!/bin/bash

mkdir -p $GOPATH/src/github.com/kata-containers/
cd $GOPATH/src/github.com/kata-containers/
git clone https://github.com/kata-containers/agent
cd agent
git checkout 1.10.0