
sudo ip l del dev vxlan_1043
sudo ip l del dev wg100 
sudo iptables -t mangle -F 
sudo ip rule del fwmark 0x413 
sudo ip route del 0.0.0.0/0 via 192.168.88.1 table 1043
sudo ip route del 192.168.88.33 dev enp7s0 table 1043

sudo ip route del 0.0.0.0/0 via 192.168.100.1 table 1043
sudo ip route del 192.168.100.33 dev enp0s8 table 1043

