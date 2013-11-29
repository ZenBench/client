#!/bin/sh

HOSTNAME=`hostname`

if [ "$1" = "clean" ] ; then
	make clean
	exit
fi

echo "$HOSTNAME"

case "$HOSTNAME" in
	rcf)
		cp Makefile.rcf Makefile
		make -f Makefile.rcf irix-mips64-r10k-cc;
		;;
	sandhills|bugeater|prairiefire)
		cp Makefile.linux Makefile
		make -f Makefile.linux linux-x86-mmx-elf;
		;;
esac


