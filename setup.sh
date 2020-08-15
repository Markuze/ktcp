echo 2,5557 > /proc/cbn/cbn_proc

sudo iptables -D PREROUTING 1 -t nat
sudo iptables -I PREROUTING -t nat -i gue+ -p tcp -m mark --mark 2 -j REDIRECT --to-ports 5557

#iptables -t mangle -N DIVERT
#iptables -t mangle -I PREROUTING -p tcp -m socket -j DIVERT
#iptables -t mangle -A DIVERT -j MARK --set-mark 0x1000
#iptables -t mangle -A DIVERT -j ACCEPT
#
#ip rule add fwmark 0x1000 lookup 100
#ip route add local 0.0.0.0/0 dev lo table 100
