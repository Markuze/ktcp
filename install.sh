#!/bin/bash

[ -z "$pool_size" ] && pool_size=512

git rev-parse --git-dir 2>/dev/null

[ "$?" -eq 0 ] && git=1
[ -z "$git" ] || version=`git rev-parse --short HEAD`

if [ -n "$1" ]; then
	version=$1
	echo "found version parameter: $version"
fi

[ -z "$version" ] && version='debug'

sed -i "s/__KTCP_VERSION__/$version/g" cbn_common.h

make
if [ "$?" != 0 ]; then
	RED='\033[1;31m'
	NC='\033[0m' # No Color
	echo
	echo -e "${RED}Please make sure this kernel has the cbn conntrack patches!!!${NC}"
	echo
	exit
fi

[ -z "$git" ] || git checkout cbn_common.h

sudo insmod cbn_split.ko pool_size=$pool_size

sudo sh -c 'echo 0 > /proc/sys/kernel/hung_task_timeout_secs'
sudo sh -c 'echo 1 > /proc/sys/kernel/ftrace_dump_on_oops'

echo "ktcp installation complete"
