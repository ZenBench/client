#!/bin/bash -x
LOAD=$(uptime |cut -d "," -f 3|awk '{print $3}')
CPU_TYPE=$(cat /proc/cpuinfo  |grep "model name"|cut -d ":" -f 2|head -n 1) 
CPU_MHZ=$(cat /proc/cpuinfo  |grep "cpu MHz" |cut -d ":" -f 2 |head -n 1)
CPU_MHZ_2=$(dmidecode -s processor-frequency|head -n 1)
CPU_NB=$(cat /proc/cpuinfo  |grep "^processor"|wc -l)
CPU_CACHE=$(cat /proc/cpuinfo  |grep "cache size" |cut -d ":" -f 2|head -n 1)
RAM_TOTAL=$(free -m |grep "^Mem:" |awk '{print $2}')
RAM_FREE=$(free -m |grep "\-/+ buffers/cache"|awk '{print $4}')
RAM_NBDIM=$(dmidecode -t memory |grep "Locator: DIM" |wc -l)
RAM_TYPE=$(dmidecode --type 17 |grep Type: |cut -d ":" -f 2 |head -n 1)
RAM_FREQ=$(dmidecode --type 17 |grep Speed: |cut -d ":" -f 2 |sort -nk1 |head -n 1)


