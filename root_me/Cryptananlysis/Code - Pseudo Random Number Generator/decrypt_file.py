#!/usr/bin/python3

import tarfile
import magic

keys_list = []

with open('keys_list', 'r') as f:
    for l in f:
        key = l.strip()
        keys_list.append(key)

def check_format(filename):
    if tarfile.is_tarfile(filename):
        f = tarfile.open(filename)
        for info in f:
            if info.isdir():
                return True
            elif info.isfile():
                return True
            else:
                return False

file = "./random_generator/oDjbNkIoLpaMo.bz2.crypt"

file_bytes = bytearray(open(file, 'rb').read())

for key in keys_list:
    new_f = []
    l = len(key)
    print("Trying - %s" % key)
    for i, x in enumerate(file_bytes):
        # print(x)
        new_f.append(hex(ord(key[i%l]) ^ x))

    result = bytes([int(x,0) for x in new_f])
    # print(result)
    with open("output.bz2", "wb") as newFile:
        newFile.write(result)
    # if check_format("output.bz2") is True:
    #     print("Found - %s" % key)
    #     break
    if 'bzip2 compressed data' in magic.from_file('output.bz2'):
        print("Found - %s" % key)
        break
    
# Use ./brute with any file to generate keys_list file using >
# Broken: key is - aM5IkP4AdQzi48qtlAjCDFYn76xLD4NN