#!/bin/bash

sudo apt-get install git build-essential fakeroot libncurses5-dev libssl-dev ccache libelf-dev -y

ktcp_dev=~/ktcp/

function clone_ktcp {
	cd
	git clone https://github.com/Markuze/ktcp.git
	KTCP="$ktcp_dev"
}

[ -d "$ktcp_dev" ] && KTCP="$ktcp_dev"
[ -z "$1" ] || KTCP="$1"/ktcp/

[ -d "$KTCP" ] || clone_ktcp

source `dirname $0`/params.txt

grep -q "12 to_tun" /etc/iproute2/rt_tables
[ "$?" -eq  1 ]  && sudo bash -c 'echo 12 to_tun >> /etc/iproute2/rt_tables'

gue_port=5555

cd ~/ENV
sudo ./disable_rpfilter.sh
sudo ./enable_ipforwarding.sh

cd ~/ENV/fou/
make clean
make
./load.sh

cd $KTCP
./install.sh

sudo ip fou add port $gue_port gue

sudo ip link add name gueright type ipip \
                        remote $NEXT local $LOCAL \
                        encap gue encap-sport auto encap-dport $gue_port

sudo ip link add name gueleft type ipip \
                        remote $PREV local $LOCAL \
                        encap gue encap-sport auto encap-dport $gue_port

sudo ip link set up gueleft
sudo ip link set up gueright
sudo ip addr add dev gueleft $LOCAL
sudo ip addr add dev gueright $LOCAL

sudo ip rule add fwmark 2 table to_tun
sudo ip route add $SRC/32 dev gueleft table to_tun
sudo ip route add $SINK/32 dev gueright table to_tun

