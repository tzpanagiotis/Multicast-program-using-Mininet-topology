# Multicast-with-OpenFlow-using-Mininet-topology

This project is a python program that creates a network with two static routers and two switches supporting multicast traffic. Vagrant and VirtualBox need to be installed on your computer (operated by Windows, Linux or MAC OS), in order to create a Virtual Machine (VM). You can follow the instructions posted [here](https://developer.hashicorp.com/vagrant/tutorials/getting-started). The VagrantFile used for this project is uploaded to the directory.

After the virtual machine is up, a network with two static routers and two switches supporting multicast traffic should be created. In order to achieve that, you should run the script mininet_topology.py, by copying this file to your working directory and executing the following commands:

* chmod 777 mininet-router-multicast.py
* ./mininet-router-multicast.py

On another window, after connecting to the VM again, turn on the Ryu controller by executing the following command:

* ryu-manager multicast.py
