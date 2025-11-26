// arp_sender.h - ARP request sender using pcap_sendpacket
#ifndef ARP_SENDER_H
#define ARP_SENDER_H

#include <pcap.h>
#include <stdint.h>

int send_arp_request(pcap_t *handle,
                     const uint8_t src_mac[6],
                     const uint8_t src_ip[4],
                     const uint8_t target_ip[4]);

#endif // ARP_SENDER_H
