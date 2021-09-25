FROM ubuntu:latest

COPY bash /bash
COPY evil-kata-agent /evil-kata-agent
COPY attack.sh /attack.sh
# Since we're targeting /bin, let's put some fake binaries in the image
COPY evil_bin /ls
COPY evil_bin /ps
COPY evil_bin /rm

RUN chmod +x /attack.sh /evil-kata-agent /ls /ps /rm /bash

ENTRYPOINT ["/attack.sh"]
