#!/bin/bash
NBCPU=$1
OUT=$2
cd $(dirname $0)
cd run &&  mpirun -np $NBCPU ./john --test|egrep "^Traditional DES|^OpenBSD Blowfish (x32)|^NT MD4|^WPA PSK"|cut -d ":" -f 3 |awk '{print $1}'> $2
