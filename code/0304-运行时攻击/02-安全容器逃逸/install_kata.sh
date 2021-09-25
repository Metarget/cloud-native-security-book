#!/bin/bash
set -e -x

# 下载安装包（如果已经下载，此步可跳过）
#wget https://github.com/kata-containers/runtime/releases/download/1.10.0/kata-static-1.10.0-x86_64.tar.xz
tar xf kata-static-1.10.0-x86_64.tar.xz
rm -rf /opt/kata
mv ./opt/kata /opt
rmdir ./opt
rm -rf /etc/kata-containers
cp -r /opt/kata/share/defaults/kata-containers /etc/
# 使用Cloud Hypervisor作为虚拟机管理程序
rm /etc/kata-containers/configuration.toml
ln -s /etc/kata-containers/configuration-clh.toml /etc/kata-containers/configuration.toml
# 配置Docker
mkdir -p /etc/docker/
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
mkdir -p /etc/systemd/system/docker.service.d/
cat << EOF > /etc/systemd/system/docker.service.d/kata-containers.conf
[Service]
ExecStart=
ExecStart=/usr/bin/dockerd -D --add-runtime kata-runtime=/opt/kata/bin/kata-runtime --add-runtime kata-clh=/opt/kata/bin/kata-clh --add-runtime kata-qemu=/opt/kata/bin/kata-qemu --default-runtime=kata-runtime
EOF
# 重载配置&重新启动Docker
systemctl daemon-reload && systemctl restart docker