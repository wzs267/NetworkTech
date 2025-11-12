/*
 * display.c
 * Data packet information display module implementation
 */

#include "display.h"
#include <stdio.h>
#include <stdint.h>

/*
 * Display table header
 */
void display_header(void)
{
    printf("\n");
    printf("====================================================");
    printf("====================================================\n");
    printf("No. | ");
    printf("Source MAC         | ");
    printf("Dest MAC           | ");
    printf("Source IP          | ");
    printf("Dest IP            | ");
    printf("Pkg Checksum | ");
    printf("Calc Checksum | ");
    printf("Status\n");
    printf("----+");
    printf("--------------------+");
    printf("--------------------+");
    printf("--------------------+");
    printf("--------------------+");
    printf("------+");
    printf("----------+");
    printf("------\n");
}

/*
 * Display data packet information in formatted way
 */
void display_packet_info(int packet_num, const packet_info_t *info)
{
    /* Print packet number */
    printf("%3d | ", packet_num);

    /* Print source MAC address */
    printf("%02X:%02X:%02X:%02X:%02X:%02X | ",
           info->src_mac[0], info->src_mac[1], info->src_mac[2],
           info->src_mac[3], info->src_mac[4], info->src_mac[5]);

    /* Print destination MAC address */
    printf("%02X:%02X:%02X:%02X:%02X:%02X | ",
           info->dest_mac[0], info->dest_mac[1], info->dest_mac[2],
           info->dest_mac[3], info->dest_mac[4], info->dest_mac[5]);

    /* Print source IP address */
    printf("%3d.%3d.%3d.%3d | ",
           info->src_ip[0], info->src_ip[1], info->src_ip[2], info->src_ip[3]);

    /* Print destination IP address */
    printf("%3d.%3d.%3d.%3d | ",
           info->dest_ip[0], info->dest_ip[1], info->dest_ip[2], info->dest_ip[3]);

    /* Print checksum field value from packet */
    printf("0x%04X | ", info->packet_checksum);

    /* Print calculated checksum value */
    printf("0x%04X | ", info->calc_checksum);

    /* Print checksum verification status */
    if (info->checksum_valid) {
        printf("OK\n");
    } else {
        printf("BAD\n");
    }
}
