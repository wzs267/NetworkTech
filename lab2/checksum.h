/*
 * checksum.h
 * IP校验和计算与验证
 */

#ifndef CHECKSUM_H
#define CHECKSUM_H

#include <stdint.h>

/*
 * 计算IP首部校验和
 * 参数：
 *   - ip_header: 指向IP首部的指针
 *   - header_len: IP首部长度（以32位字为单位）
 * 返回值：计算得到的校验和值（主机字节序）
 */
uint16_t calculate_checksum(const uint8_t *ip_header, int header_len);

/*
 * 验证IP首部校验和
 * 参数：
 *   - ip_header: 指向IP首部的指针
 *   - header_len: IP首部长度（以32位字为单位）
 *   - packet_checksum: 数据包中的校验和字段值（主机字节序）
 * 返回值：1表示校验和有效，0表示无效
 */
int verify_checksum(const uint8_t *ip_header, int header_len, uint16_t packet_checksum);

#endif /* CHECKSUM_H */
