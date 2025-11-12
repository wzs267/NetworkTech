/*
 * checksum.c
 * IP校验和计算与验证的实现
 */

#include "checksum.h"
#include <string.h>

/* Windows和Linux兼容的网络字节序转换 */
#ifdef _WIN32
    #include <winsock2.h>
    #define htons(x) ((((x) & 0xFF) << 8) | (((x) >> 8) & 0xFF))
    #define ntohs(x) ((((x) & 0xFF) << 8) | (((x) >> 8) & 0xFF))
#else
    #include <arpa/inet.h>
#endif

/*
 * 计算IP首部校验和
 * 算法：
 * 1. 将校验和字段设为0
 * 2. 将IP首部按16位分组，逐组相加（32位累加）
 * 3. 将进位部分加到低16位
 * 4. 对结果按位取反
 */
uint16_t calculate_checksum(const uint8_t *ip_header, int header_len)
{
    uint32_t sum = 0;
    const uint16_t *header = (const uint16_t *)ip_header;
    int count = header_len * 2; /* 转换为16位字的个数 */

    /* 累加所有16位字 */
    while (count--) {
        uint16_t word = *header;
        sum += ntohs(word);
        header++;
    }

    /* 处理进位：将32位结果的高16位和低16位相加 */
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    /* 返回按位取反后的结果 */
    return (uint16_t)(~sum);
}

/*
 * 验证IP首部校验和
 */
int verify_checksum(const uint8_t *ip_header, int header_len, uint16_t packet_checksum)
{
    uint16_t calculated = calculate_checksum(ip_header, header_len);
    return (calculated == packet_checksum) ? 1 : 0;
}
