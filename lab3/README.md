# Lab3 - IP to MAC mapping via ARP (NPcap)

Files added:

- `main_lab3.c` : CLI program that lists devices, lets user choose one, inputs target IP, sends ARP request and waits for reply.
- `arp_sender.c`/`arp_sender.h` : construct and send ARP request frames using `pcap_sendpacket()`.
- `arp_parser.c`/`arp_parser.h` : minimal parser to extract sender MAC/IP from ARP replies.

Build (MinGW) example:

```powershell
gcc -o lab3.exe main_lab3.c arp_sender.c arp_parser.c -lws2_32 -liphlpapi -lpcap
```

Run (requires administrator):

```powershell
.
# or
.
lab3.exe
```

Notes:
- The program attempts to find adapter MAC by matching GUID in the pcap device name with Windows adapter list. If it cannot find it, it falls back to the first adapter MAC found.
- Sending packets requires administrator privileges.
- This implementation demonstrates `pcap_sendpacket()` for ARP requests and uses `pcap_next_ex()` to capture replies.
