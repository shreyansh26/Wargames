#!/bin/bash
for i in $(objdump -d ch20.bin -M intel | grep "^ " | cut -f 2); do echo -n '0x'$i',';done;
echo