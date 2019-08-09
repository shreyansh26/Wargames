#!/usr/bin/python3

img = bytearray(open('ch3.bmp', 'rb').read())
#print(img)
key = "fallen"

new_f = []
for i, x in enumerate(img):
    new_f.append(hex(ord(key[i%6]) ^ x))

result = bytes([int(x,0) for x in new_f])
# print(result)
with open("output.bmp", "wb") as newFile:
    newFile.write(result)