FROM ubuntu:latest

COPY k8s_dns_mitm.py /poc.py

RUN sed -i 's/archive.ubuntu.com/mirrors.ustc.edu.cn/g' /etc/apt/sources.list
RUN apt update && DEBIAN_FRONTEND=noninteractive apt install -y python3 python3-pip && apt clean

RUN pip3 install scapy -i https://pypi.tuna.tsinghua.edu.cn/simple --trusted-host pypi.tuna.tsinghua.edu.cn

RUN chmod u+x /poc.py

ENTRYPOINT ["/bin/bash", "-c", "/poc.py example.com "]