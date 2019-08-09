#!/bin/python

enc = open('ch7.bin').read().strip()

rot = -30

while rot < 30:
    dec = ''.join(chr(ord(c)-rot) for c in enc)
    print(rot, dec)
    rot += 1
#print(enc)
