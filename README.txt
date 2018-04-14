#SDN firewall & Video Slice

#About:
A small network is set up on the virtual machine, with mininet installed. This network contains 4 switches, each with a host, using mininetSlice.py.This is a python code that instantiates a virtual network(mininet) independenly on any system and in no time. Mininet is a network emulator that creates a realistic virtual network, running real kernel, switch and application code, on a single machine. sudo mn is the command that brings up the switches, the hosts and the controller. The code mininetSlice.py sets up the four switches with a host or more connected to each. Although, a mininet can itself create a controller to control the switches in its network, yet I have made use of a remote controller (POX) at the tcp port 6633 on the loopback ip address, so as to have some additional functionalities of a learning switch and a firewall.




#RunME
1) put the files into path "~/pox/pox/misc"
2) note that we have two controllers, thus , you must include it both
 ,open terminal, in following path "~/pox" and write the command : "./pox.py log.level --DEBUG misc.Video misc.FireWall"
3) now , in another terminal,in path "~/pox/pox/misc" run the topology using the command: "sudo python ./mininetSlice.py"
