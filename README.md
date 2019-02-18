# ARP spoofing

Perform LAN ARP spoofing against a given host

## Options and flags

- `-t`: target on both gateway and the given host
- `-n`: [seconds] time interval between two packet
- `-c`: [count] how many packets are to be sent 
- `-e`: [iface] device name

## Usage
```sh
sudo arp-spoof 192.168.43.79 -c 5 -e wlan0
```

## Misc

[Hijack HTTP traffic via ARP spoofing](https://kennico.github.io/2019/02/15/ARP-spoofing/)
