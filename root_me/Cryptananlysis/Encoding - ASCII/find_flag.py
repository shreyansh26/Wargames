#!/bin/python

with open('ch8.txt', 'r') as f:
    l = f.read().strip()
    print(l.decode('hex'))
