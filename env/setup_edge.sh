#!/bin/bash

sudo apt-get install git build-essential fakeroot libncurses5-dev libssl-dev ccache libelf-dev -y

source `dirname $0`/params.txt

grep -q "12 to_tun" /etc/iproute2/rt_tables
[ "$?" -eq  1 ]  && sudo bash -c 'echo 12 to_tun >> /etc/iproute2/rt_tables'

gue_port=5555

cd ~/ENV/
sudo ./disable_rpfilter.sh
sudo ./enable_ipforwarding.sh

cd ~/ENV/fou/
./load.sh


sudo ip fou add port $gue_port gue

sudo ip link add name gue type ipip \
                        remote $NEXT local $LOCAL \
                        encap gue encap-sport auto encap-dport $gue_port

sudo ip link set up gue
sudo ip rule add fwmark 2 table to_tun
sudo ip route add $SINK/32 dev gue table to_tun

uid=$UID

sudo iptables -A OUTPUT -t mangle -m owner --uid-owner $uid -p tcp -j MARK --set-mark 2

