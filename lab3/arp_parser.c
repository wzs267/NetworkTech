// arp_parser.c - minimal ARP packet parser
#include "arp_parser.h"
#include <string.h>
#include <stdint.h>

struct eth_hdr {
    uint8_t dst[6];
    uint8_t src[6];
    uint16_t ethertype;
} __attribute__((packed));

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
#define ARP_OP_REPLY 2

int parse_arp_packet(const uint8_t *packet, int len,
                     uint8_t out_sender_mac[6], uint8_t out_sender_ip[4])
{
    if (len < (int)(sizeof(struct eth_hdr) + sizeof(struct arp_payload))) return 0;
    const struct eth_hdr *eth = (const struct eth_hdr *)packet;
    uint16_t ethertype = (eth->ethertype << 8) | (eth->ethertype >> 8);
    if (ethertype != ETH_TYPE_ARP) return 0;

    const struct arp_payload *arp = (const struct arp_payload *)(packet + sizeof(*eth));
    uint16_t opcode = (arp->opcode << 8) | (arp->opcode >> 8);
    if (opcode != ARP_OP_REPLY) return 0;

    memcpy(out_sender_mac, arp->sender_hw, 6);
    memcpy(out_sender_ip, arp->sender_ip, 4);
    return 1;
}
