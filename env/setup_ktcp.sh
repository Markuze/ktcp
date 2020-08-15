echo 2,5557 > /proc/cbn/cbn_proc

sudo iptables -D PREROUTING 1 -t nat
sudo iptables -D PREROUTING 2 -t nat
sudo iptables -I PREROUTING -t nat -i gueleft -p tcp -m mark --mark 2 -j REDIRECT --to-ports 5557
sudo iptables -I PREROUTING -t nat -i gueright -p tcp -m mark --mark 2 -j REDIRECT --to-ports 5557

sudo iptables -t mangle -N DIVERT
sudo iptables -t mangle -I PREROUTING -p tcp -m socket -j DIVERT
sudo iptables -t mangle -A DIVERT -j MARK --set-mark 0x1000
sudo iptables -t mangle -A DIVERT -j ACCEPT

sudo ip rule add fwmark 0x1000 lookup 100
sudo ip route add local 0.0.0.0/0 dev lo table 100
