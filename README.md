# sofar
Sofar pv inverter logging sniffer tool

This tool can be used to sniff Sofar brand pv inverter logging. Information is extracted from the packets that are sent to default 'Solarman' cloud service.

You need preferably Raspberry PI to act as an access point for the inverter. Configure Raspberry wifi to access point using hostapd. Then bridge wlan0 and eth0 interfaces to br0 and enable ip forwarding. In this setup the Sofar inverter gets IP address from the home network DHCP server and starts sending data to Solarman cloud as usual.

Now the sniffer tool can be used to capture packets from the Raspberry wlan0 interface using tcpdump and some Python code. Packets containing inverter status information are decoded and can be logged in CSV format and also as raw tcpdump capture.

See the code what can be extracted from the data.
