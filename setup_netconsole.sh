#!/bin/bash

## This script configures a netconsole sender
## please read this: https://wiki.ubuntu.com/Kernel/Netconsole : to setup a receiver

if=`ifconfig|head -1|cut -d: -f1`

function usage() {
	echo "usage: sudo $0 -p <port> -i [<ip>] -h
		 port: both sender and receiver udp port
		 ip : listner ip
		 h  : only high level messages sent"

	exit -1
}

function all_msg {
	echo "Setting loglevel 8"
	dmesg -n 8
}
port=6666

while getopts ":i:p:h" o; do
	case "${o}" in
		i)
			dip=${OPTARG}
			;;
		p)
			port=${OPTARG}
			;;
		h)
			high=1
			;;
		*)
			usage
			;;
	esac
done
shift $((OPTIND-1))

[ -z "$dip" ] && usage

echo "loading netconsole, configfs"
modprobe configfs
modprobe netconsole
mount none -t configfs /sys/kernel/config &> /dev/null

[ -z "$high" ] && all_msg

listner='/sys/kernel/config/netconsole/listner'

rmdir $listner
mkdir -p $listner

cd $listner

lip=`ip address show ens4| perl -e 'while (<>) { next unless  /\Winet\W\s*([\d\.]+)/; printf "$1";}'`
gw=`arp|grep gateway|grep -o ..:..:..:..:..:..`

echo $lip > local_ip
echo $dip > remote_ip
echo $if > dev_name
echo $gw > remote_mac

echo $port > local_port
echo $port > remote_port

echo 1 > enabled
