#!/usr/bin/python

enc = open('input').read()

enc = enc.replace('\n', ' ')
enc = enc.split()
#print(enc)
for i in range(-100, 100):
    dec = ""
    flag = 0
    for j in range(0,len(enc)):
        for k in range(len(enc[j])):
            if 0 < ord(enc[j][k])+i < 256:
                dec += chr(ord(enc[j][k])+i)
            else:
                flag = 1
                break
        if flag == 1:
            break
        if flag == 0:
            dec += " "
    if flag == 0 and dec != "":
        print(dec)
