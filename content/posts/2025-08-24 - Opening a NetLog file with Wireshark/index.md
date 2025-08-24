---
title: "Opening a NetLog file with Wireshark"
date:  2025-08-24T09:00:00-04:00
draft: false
---

In November 2024, I came across a [tweet](https://x.com/NathanMcNulty/status/1858039304259514619) from Nathan McNulty which taught me something new: Chrome and Edge support capturing network data directly from within the browser and storing it to a file!

![Image](<1. Tweet.png> "Nathan McNulty's Tweet")

I did some digging and [NetLog](https://www.chromium.org/developers/design-documents/network-stack/netlog/) is great! This is a full-featured logging mechanism within the browser and it doesn't require administrator access. And it's supported in both Chrome (`chrome://net-export`) and [Edge](https://learn.microsoft.com/en-us/troubleshoot/entra/entra-id/app-integration/use-netlog-capture-network-traffic) (`edge://net-export`)!

# Wireshark Support?

NetLog's viewer is powerful, but its GUI is busy and I'm much more comfortable with using Wireshark to analyze traffic. At first glance, it seemed that NetLogs don't include a pcap of the traffic. However, when I shared this capability in the Wireshark Discord, I was gently corrected that it should be possible to convert the NetLog file Net-Export creates into something Wireshark could handle:

![Image](<2. Wireshark correction.png> "Corrected in the Wireshark Discord")

Sake Blok, one of the Wireshark core developers, expressed interest in having support for NetLog files added to Wireshark. I created a [ticket](https://gitlab.com/wireshark/wireshark/-/issues/20289) so that this wouldn't be forgotten, but this looks like a fun project so let's get started!

![Image](<3. Sake Blok interested.png> "Sake Blok interested")

NetLog is an interesting data source. It's structured as JSON, but rather than requests and responses, each browser event that occurs is emitted and stored in the JSON. So although I was able to extract and decode the byte fields with the 10 lines of Python code below, that was insufficient for getting it to a place where it could be loaded in Wireshark with the ["Import Hex Dump" feature](https://www.wireshark.org/docs/wsug_html_chunked/ChIOImportSection.html) or [`text2pcap`](https://www.wireshark.org/docs/man-pages/text2pcap.html).

```python
import base64, codecs, json
fname = "chrome-net-export-log_-_google.json"
data = open(fname).read()
net_export_json = json.loads(data)
byte_events = [event for event in net_export_json['events'] if 'params' in event and 'bytes' in event['params']]
hex_output = b""
for event in byte_events:
    event_bytes = base64.b64decode(event['params']['bytes'])
    hex_output += codecs.encode(event_bytes, "hex")
open('hexfile.dmp', 'wb').write(hex_output)
```

![Image](<4. Harder than expected.png> "Harder than expected")

Let's dive into this a little more closely. First, let's look at some plaintext traffic by starting a capture from `edge://net-export/` , opening `http://neverssl.com`, and then stopping the capture. I'll save this in `edge-net-export-log - neverssl.json`. To make visual inspection easier I pretty-printed it with <https://jsonformatter.org/json-pretty-print> and saved that as `edge-net-export-log - neverssl_pp.json`.

![Image](<5. Capture Window.png> "Capture Window")

Now that the capture is complete, we can open it with the NetLog Viewer at <https://netlog-viewer.appspot.com/>. Each "Event" listed in the viewer includes the associated sub-events. For example, **5059** represents the SOCKET and includes the TCP stream with the actual HTTP request:

![Image](<6. Entry 5059.png> "6. Entry 5059")

We can see that we have both `TCP_CONNECT` and `SOCKET_BYTES_SENT` events at `t=6317`. Since our goal is to turn this into a PCAP, let's examine the JSON to see which other fields have a `bytes` field:

```python
import base64, codecs, json, datetime
fname = "edge-net-export-log - neverssl.json"
data = open(fname).read()
net_export_json = json.loads(data)

# Extract out names for types of constants of interest
constants = net_export_json['constants']

logevent_constants = constants['logEventTypes']

flattened_logEventTypes_constants = {}
for k, v in logevent_constants.items():
    flattened_logEventTypes_constants[v] = k


# What type of events are present?
event_types_seen = set()

for event in net_export_json['events']:
    event_type_name = flattened_logEventTypes_constants[event['type']]
    if 'params' in event and 'bytes' in event['params']:
        event_types_seen.add(event_type_name)

print(len(event_types_seen))
print("\n".join(sorted(event_types_seen)))
```

And then running our code:

```bash
$ python num_fields_bytes.py
11
QUIC_SESSION_CRYPTO_FRAME_RECEIVED
SOCKET_BYTES_RECEIVED
SOCKET_BYTES_SENT
SSL_HANDSHAKE_MESSAGE_RECEIVED
SSL_HANDSHAKE_MESSAGE_SENT
SSL_SOCKET_BYTES_RECEIVED
SSL_SOCKET_BYTES_SENT
UDP_BYTES_RECEIVED
UDP_BYTES_SENT
URL_REQUEST_JOB_BYTES_READ
URL_REQUEST_JOB_FILTERED_BYTES_READ
```

This is a pretty manageable list of only 11 entries. If we filter to only those events which are based on the socket created in event 5059:  

```bash
import base64, codecs, json, datetime
fname = "edge-net-export-log - neverssl.json"
data = open(fname).read()
net_export_json = json.loads(data)

# Extract out names for types of constants of interest
constants = net_export_json['constants']
logevent_constants = constants['logEventTypes']

flattened_logEventTypes_constants = {}
for k, v in logevent_constants.items():
    flattened_logEventTypes_constants[v] = k

# 2) What type of events are present and have data when accessing neverssl?
event_types_seen = set()

for event in net_export_json['events']:
    event_type_name = flattened_logEventTypes_constants[event['type']]
    if event.get('source', {}).get('id') == 5059:
        if 'params' in event and 'bytes' in event['params']:
            event_types_seen.add((event_type_name, event['type']))

print(len(event_types_seen))
for event_type, event_type_id in sorted(event_types_seen):
print(event_type, event_type_id)
```

And then run that code:

```bash
$ python parse_net_viewer.py

2
SOCKET_BYTES_RECEIVED 79
SOCKET_BYTES_SENT 77
```

This is great! We have entry types of `SOCKET_BYTES_SENT` for data sent and `SOCKET_BYTES_RECEIVED` for data received!

So now, let's see if we can turn those into a PCAP by dumping it to a text file and using Wireshark's `text2pcap` to turn it into a PCAP file for us. First let's dump the bytes into a text file:

```python
import base64, codecs, json, datetime
fname = "edge-net-export-log - neverssl.json"
data = open(fname).read()
net_export_json = json.loads(data)

# Extract out names for types of constants of interest
constants = net_export_json['constants']

capture_start = constants['timeTickOffset']
logevent_constants = constants['logEventTypes']

flattened_logEventTypes_constants = {}
for k, v in logevent_constants.items():
    flattened_logEventTypes_constants[v] = k

# 3) Can we dump the neverssl GET request to a PCAP?

# Write plain socket data
hex_output = b""
for event in net_export_json['events']:
    event_type_name = flattened_logEventTypes_constants[event['type']]
    if event.get('source', {}).get('id') == 5059:
        if 'params' in event and 'bytes' in event['params']:
            event_bytes = base64.b64decode(event['params']['bytes'])
            event_timestamp = capture_start + int(event['source']['start_time'])
            timestamp_string = str.encode(datetime.datetime.fromtimestamp(event_timestamp/1000).strftime("%H:%M:%S.%f"))
            if event_type_name == 'SOCKET_BYTES_RECEIVED':
                hex_output += b'i ' + timestamp_string + b" " + codecs.encode(event_bytes, "hex") + b'\n'
            elif event_type_name == 'SOCKET_BYTES_SENT':
                hex_output += b'o ' + timestamp_string + b" " + codecs.encode(event_bytes, "hex") + b'\n'
	
open('neverssl.dmp', 'wb').write(hex_output)
```

Then run Wireshark's [text2pcap](https://www.wireshark.org/docs/man-pages/text2pcap.html) to create a PCAP file:

```bash
text2pcap -t "%H:%M:%S.%f" -r "(?<dir>[io])\s(?<time>\d+:\d\d:\d\d.\d+)\s(?<data>[0-9a-fA-F]+)" neverssl.dmp output.pcapng
```

And then open the PCAP file in Wireshark:

![Image](<7. First attempt at text2pcap.png> "First attempt at text2pcap")

We have a valid PCAP file, but it didn't dissect the content because it's interpreting the HTTP GET as our Ethernet header. Let's try this again, this time generating dummy Ethernet, IP (as port 12345 to port 80), and TCP headers:


```bash
text2pcap -E ether -T 80,12345 -t "%H:%M:%S.%f" -r "(?<dir>[io])\s(?<time>\d+:\d\d:\d\d.\d+)\s(?<data>[0-9a-fA-F]+)" neverssl.dmp output.pcapng
```

and again opening the PCAP file in Wireshark:

![Image](<8. Second attempt at text2pcap.png> "Second attempt at text2pcap")

Now this is a great start. But, there's room for improvement because we had to:

1. Add dummy Ethernet headers
2. Add dummy source and destination IPs
3. Add dummy TCP headers and specify the ports
4. Manually extract the ID from the capture file and only generate a PCAP for a single capture.

There's no way around adding dummy Ethernet headers - NetLog is operating at a higher protocol layer than that. But let's tackle the rest of these. First, let's print out a listing of all the relevant entries for the socket used to connect to NeverSSL.com:  

```python
hex_output = b""
for event in net_export_json['events']:
    event_type_name = flattened_logEventTypes_constants[event['type']]
    if event.get('source', {}).get('id') == 5059:
        print(event_type_name, event['type'])
        if 'params' in event and 'bytes' in event['params']:
            event_bytes = base64.b64decode(event['params']['bytes'])
            event_timestamp = capture_start + int(event['source']['start_time'])
            timestamp_string = str.encode(datetime.datetime.fromtimestamp(event_timestamp/1000).strftime("%H:%M:%S.%f"))
            if event_type_name == 'SOCKET_BYTES_RECEIVED':
                hex_output += b'i ' + timestamp_string + b" " + codecs.encode(event_bytes, "hex") + b'\n'
            elif event_type_name == 'SOCKET_BYTES_SENT':
                hex_output += b'o ' + timestamp_string + b" " + codecs.encode(event_bytes, "hex") + b'\n'
	
open('neverssl.dmp', 'wb').write(hex_output)
```

And running our code:

```bash
> python parse_net_viewer.py
SOCKET_ALIVE 41
TCP_CONNECT 47
TCP_CONNECT_ATTEMPT 48
TCP_CONNECT_ATTEMPT 48
TCP_CONNECT 47
SOCKET_IN_USE 50
SOCKET_BYTES_SENT 77
SOCKET_BYTES_RECEIVED 79
SOCKET_IN_USE 50
SOCKET_IN_USE 50
SOCKET_BYTES_SENT 77
SOCKET_BYTES_RECEIVED 79
SOCKET_IN_USE 50
SOCKET_IN_USE 50
SOCKET_BYTES_SENT 77
SOCKET_BYTES_RECEIVED 79
SOCKET_IN_USE 50
```

In the NetLog viewer app, we can see that the source port was `57121`. In our pretty-printed JSON file, we can see how that's stored:  

```json
{
    "params": {
        "local_address": "192.168.1.206:57121",
        "remote_address": "34.223.124.45:80"
    },
    "phase": 2,
    "source": {
        "id": 5059,
        "start_time": "348415053",
        "type": 9
    },
    "time": "348418120",
    "type": 47
},
```

OK, so now we see we can extract the IPs and ports from the `TCP_CONNECT` event. So we could add those IPs and ports to our command-line parameters for `text2pcap`, but that would mean running `text2pcap` once per TCP connection. There's no better way to do it with `text2pcap` either, because `text2pcap` doesn't support storing the connection metadata for multiple connections within a single dump. So let's try using [Scapy](https://scapy.net/) instead to generate our PCAP. Scapy is a Python library for low-level packet manipulation. Since it doesn't support automatic handling of TCP sequence and acknowledgement numbers, I used an LLM to generate `TCPSessionBuilder.py`:  

```python
from scapy.all import *

class TCPSessionBuilder:
    def __init__(self, client_ip, server_ip, client_port, server_port, client_seq=1000, server_seq=20000, ipv4=True):
        self.client_ip = client_ip
        self.server_ip = server_ip
        self.client_port = client_port
        self.server_port = server_port
        self.client_seq = client_seq
        self.server_seq = server_seq
        self.ipv4 = ipv4
        self.packets = []

    def _ip_layer(self, src, dst):
        if self.ipv4:
            return IP(src=src, dst=dst)
        else:
            return IPv6(src=src, dst=dst)

    def _build(self, src, dst, sport, dport, flags, seq, ack, payload=b""):
        ip = self._ip_layer(src, dst)
        return ip / \
               TCP(sport=sport, dport=dport, flags=flags, seq=seq, ack=ack) / \
               payload

    def add_handshake(self):
        self.packets.append(
            self._build(self.client_ip, self.server_ip, self.client_port, self.server_port, "S", self.client_seq, 0)
        )
        self.packets.append(
            self._build(self.server_ip, self.client_ip, self.server_port, self.client_port, "SA",
                        self.server_seq, self.client_seq + 1)
        )
        self.packets.append(
            self._build(self.client_ip, self.server_ip, self.client_port, self.server_port, "A",
                        self.client_seq + 1, self.server_seq + 1)
        )
        self.client_seq += 1
        self.server_seq += 1

    def add_client_payload(self, payload):
        pkt = self._build(self.client_ip, self.server_ip, self.client_port, self.server_port,
                          "PA", self.client_seq, self.server_seq, payload)
        self.packets.append(pkt)
        self.client_seq += len(payload)
        return pkt

    def add_server_payload(self, payload):
        pkt = self._build(self.server_ip, self.client_ip, self.server_port, self.client_port,
                          "PA", self.server_seq, self.client_seq, payload)
        self.packets.append(pkt)
        self.server_seq += len(payload)
        return pkt

    def close_session(self):
        packets = []
        packets.append(
            self._build(self.client_ip, self.server_ip, self.client_port, self.server_port, "F",
                        self.client_seq, self.server_seq)
        )
        packets.append(
            self._build(self.server_ip, self.client_ip, self.server_port, self.client_port, "FA",
                        self.server_seq, self.client_seq + 1)
        )
        packets.append(
            self._build(self.client_ip, self.server_ip, self.client_port, self.server_port, "A",
                        self.client_seq + 1, self.server_seq + 1)
        )
        self.packets.extend(packets)
        return packets

    def save(self, filename="tcp_session.pcap"):
        wrpcap(filename, self.packets)

```

Next, let's parse the NetLog file, this time using Scapy to generate the pcap for us entirely:

```python
import base64, codecs, json, datetime
import TCPSessionBuilder
from scapy.all import *

fname = "edge-net-export-log - neverssl.json"
with open(fname) as fh:
    net_export_json = json.loads(fh.read())

# Extract out names for types of constants of interest
constants = net_export_json['constants']

capture_start = constants['timeTickOffset']
logevent_constants = constants['logEventTypes']

flattened_logEventTypes_constants = {}
for k, v in logevent_constants.items():
    flattened_logEventTypes_constants[v] = k

# Can we also include the connection info?

connections_seen = {}
packets = []
hex_output = b""
for event in net_export_json['events']:
    event_type_name = flattened_logEventTypes_constants[event['type']]
    if event.get('source', {}).get('id') == 5059:
        event_id = event.get('source', {}).get('id')
        print(event_type_name, event['type'])
        if event_type_name == "TCP_CONNECT" and "local_address" in event['params'] and "remote_address" in event['params']:
            src_ip, src_port = event['params']['local_address'].rsplit(":", 1)
            dest_ip, dest_port = event['params']['remote_address'].rsplit(":", 1)
            sess = TCPSessionBuilder.TCPSessionBuilder(src_ip, dest_ip, int(src_port), int(dest_port))
            connections_seen[event_id] = sess
        
        elif event_type_name == 'SOCKET_BYTES_RECEIVED':
            sess = connections_seen[event_id]
            event_bytes = base64.b64decode(event['params']['bytes'])
            pkt = sess.add_client_payload(event_bytes)
            packets.append(pkt)
            
        elif event_type_name == 'SOCKET_BYTES_SENT':
            sess = connections_seen[event_id]
            event_bytes = base64.b64decode(event['params']['bytes'])
            sess.add_server_payload(event_bytes)
            pkt = sess.add_client_payload(event_bytes)
            packets.append(pkt)
        
wrpcap('neverssl2.pcap', packets)
```

And success! While we still had to spoof the ethernet frame and sequence numbers, we now have accurate IPs and ports and have laid the groundwork for supporting multiple connections within a single capture:

![Image](<9. Scapy success 1.png> "Scapy success")

Now let's add a second tracker for UDP connections with our new `ScapySessionBuilder.py`

```python
from scapy.all import *

class UDPSessionBuilder:
    def __init__(self, client_ip, server_ip, client_port, server_port, client_seq=1000, server_seq=20000, ipv4=True):
        self.client_ip = client_ip
        self.server_ip = server_ip
        self.client_port = client_port
        self.server_port = server_port
        self.ipv4 = ipv4
        self.packets = []

    def _ip_layer(self, src, dst):
        if self.ipv4:
            return IP(src=src, dst=dst)
        else:
            return IPv6(src=src, dst=dst)

    def _build(self, src, dst, sport, dport, payload=b""):
        ip = self._ip_layer(src, dst)
        return ip / \
               UDP(sport=sport, dport=dport) / \
               payload

    def add_client_payload(self, payload):
        pkt = self._build(self.client_ip, self.server_ip, self.client_port, self.server_port,
                          payload)
        self.packets.append(pkt)
        return pkt

    def add_server_payload(self, payload):
        pkt = self._build(self.server_ip, self.client_ip, self.server_port, self.client_port,
                          payload)
        self.packets.append(pkt)
        return pkt

    def save(self, filename="udp_session.pcap"):
        wrpcap(filename, self.packets)


class TCPSessionBuilder:
    def __init__(self, client_ip, server_ip, client_port, server_port, client_seq=1000, server_seq=20000, ipv4=True):
        self.client_ip = client_ip
        self.server_ip = server_ip
        self.client_port = client_port
        self.server_port = server_port
        self.client_seq = client_seq
        self.server_seq = server_seq
        self.ipv4 = ipv4
        self.packets = []

    def _ip_layer(self, src, dst):
        if self.ipv4:
            return IP(src=src, dst=dst)
        else:
            return IPv6(src=src, dst=dst)

    def _build(self, src, dst, sport, dport, flags, seq, ack, payload=b""):
        ip = self._ip_layer(src, dst)
        return ip / \
               TCP(sport=sport, dport=dport, flags=flags, seq=seq, ack=ack) / \
               payload

    def add_handshake(self):
        self.packets.append(
            self._build(self.client_ip, self.server_ip, self.client_port, self.server_port, "S", self.client_seq, 0)
        )
        self.packets.append(
            self._build(self.server_ip, self.client_ip, self.server_port, self.client_port, "SA",
                        self.server_seq, self.client_seq + 1)
        )
        self.packets.append(
            self._build(self.client_ip, self.server_ip, self.client_port, self.server_port, "A",
                        self.client_seq + 1, self.server_seq + 1)
        )
        self.client_seq += 1
        self.server_seq += 1

    def add_client_payload(self, payload):
        pkt = self._build(self.client_ip, self.server_ip, self.client_port, self.server_port,
                          "PA", self.client_seq, self.server_seq, payload)
        self.packets.append(pkt)
        self.client_seq += len(payload)
        return pkt

    def add_server_payload(self, payload):
        pkt = self._build(self.server_ip, self.client_ip, self.server_port, self.client_port,
                          "PA", self.server_seq, self.client_seq, payload)
        self.packets.append(pkt)
        self.server_seq += len(payload)
        return pkt

    def close_session(self):
        packets = []
        packets.append(
            self._build(self.client_ip, self.server_ip, self.client_port, self.server_port, "F",
                        self.client_seq, self.server_seq)
        )
        packets.append(
            self._build(self.server_ip, self.client_ip, self.server_port, self.client_port, "FA",
                        self.server_seq, self.client_seq + 1)
        )
        packets.append(
            self._build(self.client_ip, self.server_ip, self.client_port, self.server_port, "A",
                        self.client_seq + 1, self.server_seq + 1)
        )
        self.packets.extend(packets)
        return packets

    def save(self, filename="tcp_session.pcap"):
        wrpcap(filename, self.packets)
```

And we can get rid of that ID filter so the script generates a complete PCAP:

```python

import base64, codecs, json, datetime
import ScapySessionBuilder
from scapy.all import *

fname = "edge-net-export-log - neverssl.json"
with open(fname) as fh:
    net_export_json = json.loads(fh.read())

# Extract out names for types of constants of interest
constants = net_export_json['constants']

capture_start = constants['timeTickOffset']
logevent_constants = constants['logEventTypes']

flattened_logEventTypes_constants = {}
for k, v in logevent_constants.items():
    flattened_logEventTypes_constants[v] = k

# 4) Can we also include the connection info?

TCP_connections_seen = {}
UDP_connections_seen = {}
# For UDP, we don't have a single connection with both the local and remote address, so we'll need a mapping of IDs to local address
# So we can build the connection objects.
UDP_connection_ids_to_remote_address = {}

packets = []
hex_output = b""
for event in net_export_json['events']:
    event_type_name = flattened_logEventTypes_constants[event['type']]
    event_id = event.get('source', {}).get('id')
    # print(event_type_name, event['type'])
    # There can be multiple TCP_CONNECT lines - we cheat by only storing the final one which includes both the local and remote addresses
    if event_type_name == "TCP_CONNECT" and "local_address" in event['params'] and "remote_address" in event['params']:
        src_ip, src_port = event['params']['local_address'].rsplit(":", 1)
        dest_ip, dest_port = event['params']['remote_address'].rsplit(":", 1)
        sess = ScapySessionBuilder.TCPSessionBuilder(src_ip, dest_ip, int(src_port), int(dest_port))
        TCP_connections_seen[event_id] = sess
    
    elif event_type_name == 'SOCKET_BYTES_RECEIVED':
        sess = TCP_connections_seen.get(event_id)
        if not sess:
            continue
        event_bytes = base64.b64decode(event['params']['bytes'])
        pkt = sess.add_client_payload(event_bytes)
        packets.append(pkt)
        
    elif event_type_name == 'SOCKET_BYTES_SENT':
        sess = TCP_connections_seen.get(event_id)
        if not sess:
            continue
        event_bytes = base64.b64decode(event['params']['bytes'])
        sess.add_server_payload(event_bytes)
        pkt = sess.add_client_payload(event_bytes)
        packets.append(pkt)

    elif event_type_name == 'SOCKET_CLOSED':
        sess = TCP_connections_seen.get(event_id)
        if not sess:
            continue
        pkts = sess.close_session()
        packets.extend(pkts)

    elif event_type_name == 'UDP_BYTES_RECEIVED':
        sess = UDP_connections_seen.get(event_id)
        if not sess:
            continue
        event_bytes = base64.b64decode(event['params']['bytes'])
        pkt = sess.add_client_payload(event_bytes)
        packets.append(pkt)
        
    elif event_type_name == 'UDP_BYTES_SENT':
        sess = UDP_connections_seen.get(event_id)
        if not sess:
            continue
        event_bytes = base64.b64decode(event['params']['bytes'])
        sess.add_server_payload(event_bytes)
        pkt = sess.add_client_payload(event_bytes)
        packets.append(pkt)

    elif event_type_name == 'UDP_CONNECT' and 'params' in event and "address" in event['params']:
        UDP_connection_ids_to_remote_address[event_id] = event['params']['address']

    elif event_type_name == 'UDP_LOCAL_ADDRESS' and 'params' in event and "address" in event['params']:
        local_address = event['params']['address']
        remote_address = UDP_connection_ids_to_remote_address[event_id]
        
        src_ip, src_port = local_address.rsplit(":", 1)
        dest_ip, dest_port = remote_address.rsplit(":", 1)
        sess = ScapySessionBuilder.UDPSessionBuilder(src_ip, dest_ip, int(src_port), int(dest_port))
        UDP_connections_seen[event_id] = sess

wrpcap('neverssl3.pcap', packets)
```

And amazing! We now have full reconstruction of our TCP and UDP data, as can be seen in Wireshark's Protocol Hierarchy:

![Image](<10.Wireshark Protocol Hierarchy.png> "Wireshark Protocol Hierarchy")

Now, this was all plaintext traffic. However, the NetLog has the decrypted data too in `SSL_SOCKET_BYTES_SENT` and `SSL_SOCKET_BYTES_RECEIVED` events. What would it take to add that to our PCAP?

![Image](<11. NetLog decrypted data.png> "NetLog decrypted data")

The one gotcha here is that the decrypted traffic uses the same ports as encrypted traffic. However, if we were to include it within the same TCP session, Wireshark's TCP reassembly would get mixed up about which is which. So instead, I followed Sake Blok's recommendation to rewrite the decrypted traffic to a new TCP session on TCP port 44380, so that Wireshark reassembles each TCP stream separately.

![Image](<12. Decrypted data in Wireshark.png> "Decrypted data in Wireshark")

And success!

Unfortunately, this seems to be as far as we can take the Python script for now. Although NetLog supports viewing QUIC session details, it does not include decrypted bytes for those, so we don't have an easy way to convert that data to a PCAP for Wireshark.

# Wiretap

Now that I had a functional prototype for parsing NetLog files in Python, I was ready to begin developing the Wireshark code in C.

Sake Blok had written that the NetLog file handler should be written as a Wiretap module. But what is Wiretap? Wireshark's READMEs described Wiretap as a library used for reading and writing capture files in various formats. They created it because libpcap only supported reading pcap files and the Wireshark team needed to support more input file types.

I've never developed for Wiretap before and the Wiretap module was only documented with two README files and whatever data was available in the code. So I decided to write a dummy Wiretap module, to better understand how Wiretap works. Once I had the sample code working it seemed like something that would be useful for others. The Wireshark developers agreed and so [merged](https://gitlab.com/wireshark/wireshark/-/merge_requests/20779) <!--# and then [remove the legacy README files](https://gitlab.com/wireshark/wireshark/-/merge_requests/20928))--> in my sample and documentation to the [Wireshark Developer's Guide](https://www.wireshark.org/docs/wsdg_html/#ChapterWiretap) as a new Wiretap chapter.

The NetLog file format is JSON-based and Wireshark already has a [Wiretap module for loading in JSON files](https://gitlab.com/wireshark/wireshark/-/blob/master/wiretap/json.c). Therefore, the obvious starting point was to reuse the JSON parsing code, especially because unlike Python, C does not have a built-in function for parsing JSON. However, the JSON Wiretap module is not as useful as I'd like because the JSON Wiretap module treats the entire JSON file as a single packet, and hands that off to the JSON dissector. This can be seen in the packet list below:

![Image](<13. JSON file in Wireshark.png> "JSON file in Wireshark")

What we need is a little different - we need to be able to load a NetLog JSON file and display the TCP and UDP packets embedded within it. However, the JSON Wiretap module was still useful because it pointed me to `wsjson.h`, Wireshark's JSON parsing library. `wsjson.h` is an interface over a vendorized copy of [Serge Zaitsev's jsmn library](https://github.com/zserge/jsmn). I've never used the `wsjson` functions before and they also weren't as documented as I'd like, so I submitted another [merge request to document the rest of wsjson](https://gitlab.com/wireshark/wireshark/-/merge_requests/20883).

# Implementing netlog's open(), read(), and seek_read()

So now with an understanding of how to write a Wiretap module and functions for extracting JSON data, I'm finally ready to begin implementing the NetLog Wiretap code.

To summarize the [Wireshark Developer's Guide](https://www.wireshark.org/docs/wsdg_html/#ChapterWiretap), Wiretap mostly uses three functions: An `open` function to determine if this is the correct Wiretap module for a file, a `read` function that reads the next packet from a file, and a `seek_read` function to read a packet from the specified offset in a file. After the `open` function is used to confirm a match, Wireshark calls the `read` function in a loop to read the entire file and then calls `seek_read` to generate the display when an individual entry is selected from the list of packets.

Wireshark requires a one-to-one mapping between each call to `read` or `seek_read` and a retrieved 'packet'. However, JSON data doesn't lend itself to being accessed across multiple function calls. We certainly wouldn't want to re-parse the entire JSON file on each call.

My initial idea was to have the first call to `read` parse all the packets, append the packets to a list, and then on each successive call to `read`, return the next packet. But storing all of the packet data in-memory seems inefficient [^3gpp]. But what's a lot smaller than the entire packet data (especially when it can be multiple KB per packet) is to instead store *where* in the file the event's JSON object is located and its *length* in bytes. Of course, there's some contextual data needed as well - we need to know which TCP or UDP connection these bytes are associated with. But that is still much smaller than the entire packet with the complete IPv4/IPv6 and TCP/UDP headers and payload. We can cache that list inside `wth-priv` which persists across calls, and instead of `seek_read`'s 'offsets' referring to the byte offset in the file they will instead be pseudo-offsets for the list index. This made implementing both `read` and `seek_read` straightforward: For `read`, we can cache the last index returned and on each call to `read`, return the packet at the index and then increment the index. On a call to `seek_read`, we simply return the packet at the specified index (as the offset value). As [Glib's List](https://docs.gtk.org/glib/struct.List.html) is implemented as a doubly-linked list, random access is inefficient, so I used a [HashTable](https://docs.gtk.org/glib/struct.HashTable.html) to map the index (offset) to the associated `JSONPacket` object.

[^3gpp]: I have since learned from Anders Broman that the 3gpp-nettrace parser actually converts its XML to a temporary pcap-ng file which is then parsed as input. That might have been an acceptable alternative.

With that, we now have a fully operational Wiretap module for NetLog!

![Image](<14. NetLog parser operational.png> "NetLog Wiretap module works!")


# Performance Challenges
The quote I've heard is "Performance is not a requirement, it's a feature." However, if the application runs too slowly, performance is escalated to a requirement.

In my first implementation, the code to load the NetLog files was horrifically slow. My test file was a 110 MB JSON file, which contained about 24 MB worth of network data, as determined by converting it to a PCAP with the earlier Python script. With a debug build of Wireshark, it took about 5 minutes just to load the JSON data and 9 more minutes to load the packet view. This seems pretty inefficient and any performance improvements made to the debug build should also be replicated over to the release build. So, how can we speed this up?

My first implementation read the NetLog file into memory and validated the JSON in the `open` function. Then, it would read and reparse the NetLog file again in `read`. Removing the duplicative validation by moving the parsing to the `open` function (as described above) enabled me to remove the redundant parsing, lowering the test runtime from 15 minutes to a little over 13 minutes. I then switched to a release build to see what a user would experience, and with those optimizations, was down to 5.5 minutes. Much better, but still too slow.

The next suggestion was from Michael Mann, that the JSON iteration was inefficient because it too was using a linked-list approach. Each time I was calling `json_get_array_index` to access the next JSON object, the JSON parser was walking through the entire array of JSON tokens until it reached the *n*th element. This was especially slow because there were more than 75,000 entries in my 110 MB file's JSON array. The more efficient approach would be to track the element number ourselves and repeatedly call `json_get_next_object` to increment our position. The only wrinkle was that the `json_get_next_object` function wasn't in the header file, but [one short MR later](https://gitlab.com/wireshark/wireshark/-/merge_requests/20964) and it was available for use (and was then [used](https://gitlab.com/wireshark/wireshark/-/merge_requests/20964)). Using `json_get_next_object` for iteration took us from 5.5 minutes to just over 2 minutes! While still slow, this was a much more acceptable runtime for a 100+ MB JSON file.

To maintain proper sequence numbers, I also needed to get the length of the data transmitted in each event. Although I didn't need the data itself, I initially took the easy approach to decode the base64 data with Glib's `g_base64_decode` and then get the length of the decoded bytes. However, this was pretty inefficient. Besides the base64 parsing, `g_base64_decode` was also allocating a new string. I realized a faster approach would be to examine the length of the base64 data and remove the padding, which would allow me to calculate the data's length without needing to fully decode the base64 data. And then while I was polishing the code, I realized that the JSON events included a `byte_count` field, which contained the number of bytes directly, without any further parsing needed. While this improvement did not make a significant performance difference, it seems reasonable that reading a short integer from the JSON would be faster than extracting the base64 data, decoding it, and then measuring its length.

# Design Decisions

During the implementation, I made a few design decisions. The first was that for TCP sessions, we needed sequence numbers. The NetLog data itself didn't include sequence numbers, but to ease review, I defined placeholders for the client's starting sequence number as `10000` and the server's starting sequence number as `20000`.

The next was that although the NetLog files include CONNECT messages for establishing TCP sockets, I didn't bother creating pseudo-handshakes for the packets, because generating handshakes for successful connections doesn't add value for higher-level traffic analysis. I likewise didn't bother generating FINs for closed sockets, even though the information was available for the same reason.

However, the one situation where TCP SYNs are interesting is when the browser entirely fails to establish the TCP connection, as the only record of that connection is the TCP SYN. Unfortunately, the NetLog events there only include the attempt, but do not include the source port, as can be seen below. I wasn't a fan of generating and using random source ports, as that might introduce confusion and could possibly conflict with other traffic.

![Image](<15. Failed TCP handshake.png> "Failed TCP handshake events")

Another design decision was with how to handle SSL traffic. As mentioned above, the challenge is that decrypted traffic uses the same ports as encrypted traffic. However, if we were to reuse the same source port, Wireshark's TCP reassembly would get mixed up about how to reassemble the TCP stream. So instead, I followed Sake Blok's recommendation to rewrite the decrypted traffic to a new TCP session on TCP port 44380, so that the decrypted traffic would be available within Wireshark.

The [JSON Wiretap module](https://gitlab.com/wireshark/wireshark/-/blob/master/wiretap/json.c) defines a `MAX_FILE_SIZE` of 50 MB and fails to parse larger files. That seemed a bit small, so for the NetLog module, I set the max size to 120 MB. While that's still an arbitrary size, setting a max size seemed prudent as the entire file needs to be loaded into memory at once to load the JSON and [Wiretap modules can't be configured by a preference setting](https://gitlab.com/wireshark/wireshark/-/issues/20234).

The last design decision was how to handle NetLog files without packet data. When a file is opened, Wireshark runs the file through the list of Wiretap modules to find the first one which matches the format. As NetLog files are a type of JSON file, we needed to put NetLog above JSON. However, we also don't want to grab everything, as some JSON files might be intended for the JSON module. To balance I decided upon was that if a file has the NetLog constants and at least one packet, to process the file with the NetLog Wiretap module. Otherwise, the data will be passed to the next Wiretap module, which is likely to be the JSON dissector.

# Conclusion

This was a fun project to learn about NetLog files and add support for them in Wireshark. This feature will be included in Wireshark 4.6.0 (expected release in October 2025). If you’d like to try it out sooner, you can download one of Wireshark’s nightly builds from https://www.wireshark.org/download/automated/ . 

Thank you to Sake Blok for supporting this feature, John Thacker for advice in Discord, and Michael Mann for the time spent reviewing the code, helping it get to a state to be merged, and merging the code.

# References and Further Reading

* Python Code for converting NetLog files to PCAP: https://github.com/moshekaplan/parse_netlog
* "Support ingesting packet data from Chrome/Edge net-export (NetLog files)" https://gitlab.com/wireshark/wireshark/-/issues/20289
* "wiretap: Add support for Chrome NetLog" https://gitlab.com/wireshark/wireshark/-/merge_requests/20949
* "Wireshark Developer’s Guide: Chapter 10. Wiretap" https://www.wireshark.org/docs/wsdg_html/#ChapterWiretap
* "WSDG: Add wiretap chapter" https://gitlab.com/wireshark/wireshark/-/merge_requests/20779
* "wsjson: Document and add json_get_int" https://gitlab.com/wireshark/wireshark/-/merge_requests/20883
* "Chromium source: net_log.h" https://chromium.googlesource.com/chromium/src/+/HEAD/net/log/net_log.h#298
* "NetLog: Chrome’s network logging system" https://www.chromium.org/developers/design-documents/network-stack/netlog/
* "Use NetLog as an alternative to Fiddler and HAR captures" https://learn.microsoft.com/en-us/troubleshoot/entra/entra-id/app-integration/use-netlog-capture-network-traffic
