---
title: "Opening a NetLog file with Wireshark"
date:  2025-07-29T21:00:00-04:00
draft: false
---

In November 2024, I came across a [tweet](https://x.com/NathanMcNulty/status/1858039304259514619) from Nathan McNulty which taught me something new: Chrome and Edge support capturing network data directly from within the browser and logging it to a file!

![Image](<1. Tweet.png> "Nathan McNulty's Tweet")

I did some digging and [NetLog](https://www.chromium.org/developers/design-documents/network-stack/netlog/) is great! This is a full-featured logging mechanism within the browser and it doesn't require administrator access. And it's supported in both Chrome (`chrome://net-export`) and [Edge](https://learn.microsoft.com/en-us/troubleshoot/entra/entra-id/app-integration/use-netlog-capture-network-traffic) (`edge://net-export`)!

# Wireshark Support?

NetLog is powerful, but its GUI is pretty busy and I'm much more comfortable with using Wireshark to analyze traffic. At first glance, it seemed that NetLogs don't include a pcap of the traffic. However, when I shared this capability in the Wireshark Discord, I was gently corrected that it should be possible to convert the NetLog file Net-Export creates into something Wireshark could handle:

![Image](<2. Wireshark correction.png> "Corrected in the Wireshark Discord")

Sake Blok, one of the Wireshark core developers, expressed support for adding loading the NetLog files into Wireshark. I created a [ticket](https://gitlab.com/wireshark/wireshark/-/issues/20289) so that this wouldn't be forgotten, but this looks like a fun project so let's get started!

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

So let's dive into this a little more closely. First, let's look at some plaintext traffic by starting a capture from `edge://net-export/` , opening `http://neverssl.com`, and then stopping the capture. I'll save this in `edge-net-export-log - neverssl.json`. To make visual inspection easier,  and I'll pretty-print it with <https://jsonformatter.org/json-pretty-print> and save that as `edge-net-export-log - neverssl_pp.json`.

![Image](<5. Capture Window.png> "Capture Window")

Now that the capture is complete, we can open it with the NetLog Viewer at <https://netlog-viewer.appspot.com/>. Each "Event" listed in the viewer includes the associated sub-events. For example, **5059** represents the SOCKET and includes the TCP stream with the actual HTTP request:

![Image](<6. Entry 5059.png> "6. Entry 5059")

Since our goal is to turn this into a PCAP, let's examine the JSON to see which fields have a `bytes` field:

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

This is great! We have one entry type of `SOCKET_BYTES_SENT` for data sent and `SOCKET_BYTES_RECEIVED` for data received!

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

We have a valid PCAP file, but it didn't dissect the content because it's interpreting the HTTP GET as our Ethernet header. Let's try this again, this time generating dummy Ethernet, IP, and TCP headers:


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

There's no way around adding dummy Ethernet headers - NetLog is operating at a higher protocol layer than that. But let's tackle the rest of these. First, let's print out a listing of all of the relevant entries for the socket used to connect to NeverSSL.com:  

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

In the Netlog viewer app, we can see that the source port was `57121`. In our pretty-printed JSON file, we can see how that's stored:  

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

OK, so now we see we can extract the IPs and ports from the `TCP_CONNECT` event. So we could add those IPs and ports to our command-line parameters for `text2pcap`, but that would mean running `text2pcap` once per TCP connection. There's no better way to do it with `text2pcap` either, because `text2pcap` doesn't support storing the connection metadata for multiple connections within a single dump. So let's try using Scapy instead to generate our PCAP. Scapy is a Python library for low-level packet manipaulation. Since it doesn't support automatic handling of TCP sequence and acknowledgement numbers, I used an LLM to generate `TCPSessionBuilder.py`:  

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

The one gotcha here is that the decrypted traffic uses the same ports as encrypted traffic. However, if we were to include it within the same TCP session, Wireshark's TCP reassembly would get mixed up about which is which. So instead, I followed Sake Blok's reccommendation to rewrite the decrypted traffic to a new TCP session on TCP port 44380, so that Wireshark reassembles each TCP stream separately.

![Image](<12. Decrypted data in Wireshark.png> "Decrypted data in Wireshark")

And success!

Unfortunately, this seems to be as far as we can take the Python script for now. Although NetLog supports viewing QUIC session details, it does not include decrypted bytes for those, so we don't have an easy way to convert that data to a PCAP for wireshark.

# Conclusion

This was a fun project to learn about NetLog files and how I could convert them to PCAP files so they could be opened with Wireshark. However, our work isn't done yet - the next step will be to write a [libwiretap](https://gitlab.com/wireshark/wireshark/-/blob/master/wiretap/README) module to support loading NetLog files directly in Wireshark without needing to convert them with Scapy. To be continued!

* Python Code: https://github.com/moshekaplan/parse_netlog

# References and Further Reading

* https://www.chromium.org/developers/design-documents/network-stack/netlog/
* https://learn.microsoft.com/en-us/troubleshoot/entra/entra-id/app-integration/use-netlog-capture-network-traffic
* https://gitlab.com/wireshark/wireshark/-/issues/20289
