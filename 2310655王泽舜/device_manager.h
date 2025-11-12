/*
 * device_manager.h
 * 网络设备管理模块
 */

#ifndef DEVICE_MANAGER_H
#define DEVICE_MANAGER_H

#include <pcap.h>

/*
 * 列出系统中的所有网络设备
 * 返回值：设备列表指针（pcap_if_t），失败返回NULL
 */
pcap_if_t *list_devices(void);

/*
 * 从设备列表中选择一个设备并打开
 * 参数：
 *   - all_devs: pcap_findalldevs()返回的设备列表
 *   - errbuf: 错误信息缓冲区
 * 返回值：打开的pcap句柄，失败返回NULL
 */
pcap_t *select_and_open_device(pcap_if_t *all_devs, char *errbuf);

#endif /* DEVICE_MANAGER_H */
