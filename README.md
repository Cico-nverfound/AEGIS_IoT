# AEGIS_IoT - New-gen defense device for home networks
AEGIS_IoT is a **domestic immunity appliance**, focusing on IoT devices. It constantly searches for anomalies and possible danger in behavior of IoT devices. After detection, AEGIS_IoT then responds by blocking the incriminated request, and gives a simple report, understandable by everybody, through an SML.
# Why does the world need this?
  - _Botnets_: The majority of botnets today, is built on these devices.
  - _Ease of exploit_: IoT device don't receive the same amount of updates, making them the **perfect vector and entry point** for hackers.
  - _**BIG** Lack of protection_: Today's standard technologies don't trat in the right way this kind of device, which is the main cause attackers have success in lateral movement and hacking. They remain the most hacked type of device, yet standard routers don't offer any good protection for / from them.
# How does AEGIS_IoT work?
AEGIS_IoT is always active and actively scanning for danger, and it bases itself on 4 pillar:
1. IoT related threats detection: through Suricata with IoT dedicated rules + URL malicious list feed + DNS sinkhole
2. Behavioral anomaly detection: AEGIS deetects behavior that differ from the baseline (IoT devices have a repetitive traffic, so it's easy to detect what differs from normal)
3. Active response: Trough DNS blackout and fake ARP packets, the device is unable to communicate with everyone
## AEGIS_IoT hardware
To realize this, an SBC is needed. The suggested one it's the **Raspberry pi CM5**. But why? 
  - _Scalable carrier board_: The carrier board makes it possible to adapt this project to every need.
  - _eMMC reliability at low cost_: using the Raspberry Pi 5 would increase the cost of the project, as an SSD would be necessary. The CM5 keeps costs low, making it a valid product and scalable, for commerce.
  - _Cortex-A76_: With 4 GB of RAM, it gives enough space to set up Suricata + Python engine + local SLM, on a home network (wich is typically small enough to be contained in 4 gb of RAM, to use this project on bigger networks, more RAM is needed)

