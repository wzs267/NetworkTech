// arp_sender.c - build and send ARP request frames via pcap_sendpacket
#include "arp_sender.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

// Ethernet header (14 bytes)
struct eth_hdr {
    uint8_t dst[6];
    uint8_t src[6];
    uint16_t ethertype; // network byte order
} __attribute__((packed));

// ARP payload (28 bytes for Ethernet+IPv4)
struct arp_payload {
    uint16_t htype;
    uint16_t ptype;
    uint8_t hlen;
    uint8_t plen;
    uint16_t opcode;
    uint8_t sender_hw[6];
    uint8_t sender_ip[4];
    uint8_t target_hw[6];
    uint8_t target_ip[4];
} __attribute__((packed));

#define ETH_TYPE_ARP 0x0806
#define ARP_HTYPE_ETH 1
#define ARP_PTYPE_IPV4 0x0800
#define ARP_OP_REQUEST 1

int send_arp_request(pcap_t *handle,
                     const uint8_t src_mac[6],
                     const uint8_t src_ip[4],
                     const uint8_t target_ip[4])
{
    if (!handle) return -1;

    uint8_t packet[42]; // 14 + 28
    memset(packet, 0, sizeof(packet));

    struct eth_hdr *eth = (struct eth_hdr *)packet;
    // dst = broadcast
    memset(eth->dst, 0xFF, 6);
    memcpy(eth->src, src_mac, 6);
    eth->ethertype = htons(ETH_TYPE_ARP);

    struct arp_payload *arp = (struct arp_payload *)(packet + sizeof(*eth));
    arp->htype = htons(ARP_HTYPE_ETH);
    arp->ptype = htons(ARP_PTYPE_IPV4);
    arp->hlen = 6;
    arp->plen = 4;
    arp->opcode = htons(ARP_OP_REQUEST);
    memcpy(arp->sender_hw, src_mac, 6);
    memcpy(arp->sender_ip, src_ip, 4);
    memset(arp->target_hw, 0x00, 6);
    memcpy(arp->target_ip, target_ip, 4);

    if (pcap_sendpacket(handle, packet, sizeof(packet)) != 0) {
        fprintf(stderr, "[ERROR] pcap_sendpacket failed: %s\n", pcap_geterr(handle));
        return -1;
    }

    return 0;
}
