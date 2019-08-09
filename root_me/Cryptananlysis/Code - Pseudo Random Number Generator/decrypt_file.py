#!/usr/bin/python3

import magic

keys_list = []

with open('keys_list', 'r') as f:
    for l in f:
        key = l.strip()
        keys_list.append(key)

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

    if 'bzip2 compressed data' in magic.from_file('output.bz2'):
        print("Found - %s" % key)
        break

# Use ./brute with any file to generate keys_list file using >
# Broken: key is - aM5IkP4AdQzi48qtlAjCDFYn76xLD4NN