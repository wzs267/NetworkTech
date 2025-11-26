/*
 * display.h
 * 数据包信息显示模块
 */

#ifndef DISPLAY_H
#define DISPLAY_H

#include "packet_structures.h"

/*
 * 以格式化的方式显示单个数据包的信息
 * 参数：
 *   - packet_num: 数据包序号
 *   - info: 包含解析后数据包信息的结构体
 */
void display_packet_info(int packet_num, const packet_info_t *info);

/*
 * 显示表头
 */
void display_header(void);

#endif /* DISPLAY_H */
