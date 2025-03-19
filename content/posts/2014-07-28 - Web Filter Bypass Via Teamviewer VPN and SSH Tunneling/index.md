---
title: "Web Filter Bypass Via Teamviewer VPN and SSH Tunneling"
date: 2014-07-28T08:00:00-04:00
draft: false
---

﻿
I have a cousin that lives in a community where Internet access is extremely controlled and having unrestricted Internet access is taboo. She has a special dispensation so she can work remotely, but her access is heavily restricted. She recently asked if I could find a way to repair her iPod, as it didn’t boot and needed a firmware update, but she couldn’t update the firmware through iTunes, because of the Internet filter.

So to take a quick inventory:

1. Only whitelisted websites are accessible
1. Non-HTTP ports are blocked
1. TeamViewer is accessible

So my strategy was to:

1. Create a VPN through TeamViewer ([here’s a guide](https://web.archive.org/web/20200202173202/http://www.smartpctricks.com/2013/05/how-to-setup-configure-free-vpn-virtual-private-network-with-team-viewer-vpn-client-software.html))
1. Set up an SSH server on an Ubuntu VM
1. Use Putty to connect to the SSH server through the VPN and use it as a SOCKS proxy

None of these steps are particularly difficult. Setting up Putty’s [plink](http://the.earth.li/~sgtatham/putty/latest/x86/plink.exe) for the SOCKS proxy was the most difficult step.

Here is the command to run with plink:
```
:: Connects to 192.168.1.2 on port 5900. Sets up a SOCKS proxy that listens on 127.0.0.1 port 9876 and forwards all connections through the connection to 192.168.1.2.
:: You then need to configure your system to use 127.0.0.1:9876 as a SOCKS proxy.

PLINK.EXE 192.168.1.2 -P 5900 -D 127.0.0.1:9876 -N
```

The only other gotcha is that in Windows, you need to specifically enable the SOCKS proxy, and disable all other proxies.

