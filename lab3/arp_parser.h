#ifndef ARP_PARSER_H
#define ARP_PARSER_H

#include <stdint.h>

// Parse ARP packet payload & return 1 if it's ARP reply for target_ip
int parse_arp_packet(const uint8_t *packet, int len,
                     uint8_t out_sender_mac[6], uint8_t out_sender_ip[4]);

#endif // ARP_PARSER_H
