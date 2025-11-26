/*
 * packet_structures.h
 * 定义数据包相关的结构体和常量
 */

#ifndef PACKET_STRUCTURES_H
#define PACKET_STRUCTURES_H

#include <stdint.h>

/* 以太网帧头结构（14字节） */
typedef struct {
    uint8_t dest_mac[6];      /* 目的MAC地址 */
    uint8_t src_mac[6];       /* 源MAC地址 */
    uint16_t type;            /* 帧类型（网络字节序） */
} ethernet_header_t;

/* IP数据报头结构（最少20字节） */
typedef struct {
    uint8_t version_ihl;      /* 版本(4bit) + 首部长度(4bit) */
    uint8_t dscp_ecn;         /* 区分服务代码点 + 显式拥塞通知 */
    uint16_t total_length;    /* 总长度（网络字节序） */
    uint16_t identification;  /* 标识符（网络字节序） */
    uint16_t flags_fragment;  /* 标志 + 片偏移（网络字节序） */
    uint8_t ttl;              /* 生存时间 */
    uint8_t protocol;         /* 协议类型 */
    uint16_t checksum;        /* 校验和（网络字节序） */
    uint8_t src_ip[4];        /* 源IP地址 */
    uint8_t dest_ip[4];       /* 目的IP地址 */
} ip_header_t;

/* 解析后的数据包信息结构 */
typedef struct {
    uint8_t src_mac[6];       /* 源MAC地址 */
    uint8_t dest_mac[6];      /* 目的MAC地址 */
    uint8_t src_ip[4];        /* 源IP地址 */
    uint8_t dest_ip[4];       /* 目的IP地址 */
    uint16_t packet_checksum; /* 数据报中的校验和字段值 */
    uint16_t calc_checksum;   /* 程序计算的校验和值 */
    int checksum_valid;       /* 校验和是否有效（1=有效, 0=无效） */
    uint16_t total_length;    /* IP数据报总长度 */
    uint8_t protocol;         /* 协议类型 */
    uint8_t ttl;              /* 生存时间 */
} packet_info_t;

/* 常量定义 */
#define ETHERNET_TYPE_IP    0x0800  /* IP协议的以太网类型 */
#define ETHERNET_HEADER_LEN 14      /* 以太网帧头长度 */
#define IP_HEADER_MIN_LEN   20      /* IP首部最小长度 */
#define SNAPLEN             65535   /* 快照长度（最大捕获字节数） */
#define READ_TIMEOUT        1000    /* 读超时时间（毫秒） */

#endif /* PACKET_STRUCTURES_H */
