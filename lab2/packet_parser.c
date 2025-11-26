/*
 * packet_parser.c
 * 数据包解析模块的实现
 */

#include "packet_parser.h"
#include "checksum.h"
#include <string.h>
#include <stdio.h>

/* Windows和Linux兼容的网络字节序转换 */
#ifdef _WIN32
    #include <winsock2.h>
    #define htons(x) ((((x) & 0xFF) << 8) | (((x) >> 8) & 0xFF))
    #define ntohs(x) ((((x) & 0xFF) << 8) | (((x) >> 8) & 0xFF))
#else
    #include <arpa/inet.h>
#endif

/*
 * 解析捕获的数据包
 */
int parse_packet(const uint8_t *packet_data, uint32_t packet_len, packet_info_t *info)
{
    /* 检查数据包长度是否足够以包含以太网帧头 */
    if (packet_len < ETHERNET_HEADER_LEN) {
        return -1;
    }

    /* 解析以太网帧头 */
    const ethernet_header_t *eth_header = (const ethernet_header_t *)packet_data;
    uint16_t eth_type = ntohs(eth_header->type);

    /* 只处理IP数据包 */
    if (eth_type != ETHERNET_TYPE_IP) {
        return -1;
    }

    /* 检查数据包长度是否足够以包含IP首部 */
    if (packet_len < ETHERNET_HEADER_LEN + IP_HEADER_MIN_LEN) {
        return -1;
    }

    /* 解析IP首部 */
    const ip_header_t *ip_header = (const ip_header_t *)(packet_data + ETHERNET_HEADER_LEN);

    /* 提取源和目的MAC地址 */
    memcpy(info->src_mac, eth_header->src_mac, 6);
    memcpy(info->dest_mac, eth_header->dest_mac, 6);

    /* 提取源和目的IP地址 */
    memcpy(info->src_ip, ip_header->src_ip, 4);
    memcpy(info->dest_ip, ip_header->dest_ip, 4);

    /* 提取IP首部的其他字段 */
    info->total_length = ntohs(ip_header->total_length);
    info->protocol = ip_header->protocol;
    info->ttl = ip_header->ttl;

    /* 提取数据包中的校验和 */
    info->packet_checksum = ntohs(ip_header->checksum);

    /* 计算IP首部的长度（以32位字为单位） */
    int ihl = (ip_header->version_ihl & 0x0F);  /* 取低4位 */

    /* 计算校验和 */
    info->calc_checksum = calculate_checksum((const uint8_t *)ip_header, ihl);

    /* 验证校验和 */
    info->checksum_valid = verify_checksum((const uint8_t *)ip_header, ihl, info->packet_checksum);

    return 0;
}
