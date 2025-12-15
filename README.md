# host-detector-arp-icmp

A small Python script that i made to practice some concepts that i've been studying, made for educational purposes, this is not a professional and fully functional tool.

# How it works

The script uses the netifaces library to get the user's ip address inside the selected interface (lo, wlo, eth0...),  converting the netmask to the necessary format for CIDR notation ip (conversion example: 255.255.255.0 => 24) (get_local function).

With the result, the net_scanner function will obtain the ip and mac addresses of hosts in the network through ARP and ICMP requests. Most of the addresses will be obtained by arp, the rest will be added with ICMP. All of the results will be written in a txt file for the user to interpret the data and use it as they want.

The process will only stop when the entire range of the network is tested or the user presses CTRL-C

This is a simple practice project made for testing and learning about networking, the code may be messy and can be refactored as needed.
