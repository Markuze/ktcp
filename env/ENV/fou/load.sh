make clean
make
sudo modprobe ip_tunnel
sudo modprobe ipip
sudo modprobe udp_tunnel
sudo modprobe ip6_tunnel
sudo modprobe ip6_udp_tunnel
sudo insmod ./fou.ko
