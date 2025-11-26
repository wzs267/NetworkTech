/*
 * packet_parser.h
 * 数据包解析模块
 */

#ifndef PACKET_PARSER_H
#define PACKET_PARSER_H

#include "packet_structures.h"

/*
 * 解析捕获的数据包
 * 参数：
 *   - packet_data: 完整数据包数据
 *   - packet_len: 数据包长度
 *   - info: 指向packet_info_t结构体，用于存储解析结果
 * 返回值：0表示解析成功，-1表示失败（可能不是IP数据包）
 */
int parse_packet(const uint8_t *packet_data, uint32_t packet_len, packet_info_t *info);

#endif /* PACKET_PARSER_H */
