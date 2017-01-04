pcap-ecample
------------
we extract the ethernet addresses of each packet. Only works if your driver is in monitor mode:

```
ifconfig wlan0 down
iwconfig wlan0 mode Monitor
ifconfig wlan0 up
```
build & run
-----
```
stack build
sudo stack exec pcap-example-exe --allow-different-user #Run with admin permissions, as you need to access wlan interface.
```
