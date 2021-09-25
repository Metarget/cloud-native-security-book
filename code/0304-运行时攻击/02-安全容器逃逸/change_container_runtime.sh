#!/bin/bash

if [ $1 = "kata" ]; then
    cat << EOF > /etc/docker/daemon.json
{
  "runtimes": {
    "kata-runtime": {
      "path": "/opt/kata/bin/kata-runtime"
    },
    "kata-clh": {
      "path": "/opt/kata/bin/kata-clh"
    },
    "kata-qemu": {
      "path": "/opt/kata/bin/kata-qemu"
    }
  },
  "registry-mirrors": ["https://docker.mirrors.ustc.edu.cn/"]
}
EOF
    cat << EOF > /etc/systemd/system/docker.service.d/kata-containers.conf
[Service]
ExecStart=
ExecStart=/usr/bin/dockerd -D --add-runtime kata-runtime=/opt/kata/bin/kata-runtime --add-runtime kata-clh=/opt/kata/bin/kata-clh --add-runtime kata-qemu=/opt/kata/bin/kata-qemu --default-runtime=kata-runtime
EOF
    systemctl daemon-reload && systemctl restart docker

elif [ $1 = "runc" ]; then
    rm -f /etc/systemd/system/docker.service.d/kata-containers.conf
    cat << EOF > /etc/docker/daemon.json
{
  "registry-mirrors": ["https://docker.mirrors.ustc.edu.cn/"]
}
EOF
    systemctl daemon-reload && systemctl restart docker

else 
    echo "Invalid container runtime."
fi 

