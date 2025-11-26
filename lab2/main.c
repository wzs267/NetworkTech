/*
 * main.c
 * NPcap IP data packet capture and analysis program
 * 
 * Features:
 * 1. Get and list system network devices
 * 2. User selects a device for packet capture
 * 3. Capture IP datagram and calculate checksum
 * 4. Display in table format: source/dest MAC, source/dest IP, checksum
 * 5. Exit capture with Ctrl+C
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <pcap.h>
#include <wchar.h>
#include <locale.h>
#include <io.h>
#include <fcntl.h>

#ifdef _WIN32
    #include <windows.h>
#endif

#include "packet_structures.h"
#include "device_manager.h"
#include "packet_parser.h"
#include "display.h"

/* 全局变量：用于Ctrl+C处理 */
static pcap_t *g_handle = NULL;
static volatile int g_should_stop = 0;

/*
 * 信号处理函数：捕获Ctrl+C信号
 */
static void signal_handler(int sig)
{
    printf("\n\n[信息] 收到中断信号，正在停止捕获...\n");
    g_should_stop = 1;
    if (g_handle != NULL) {
        pcap_breakloop(g_handle);
    }
}

/*
 * 数据包处理回调函数
 */
static void packet_callback(u_char *user, const struct pcap_pkthdr *pkthdr,
                            const u_char *packet)
{
    static int packet_count = 0;
    packet_count++;

    packet_info_t info;
    memset(&info, 0, sizeof(packet_info_t));

    /* 解析数据包 */
    if (parse_packet(packet, pkthdr->len, &info) == 0) {
        /* 仅在首次显示时打印表头 */
        if (packet_count == 1) {
            display_header();
        }
        display_packet_info(packet_count, &info);
    }
}

/*
 * 主函数
 */
int main(int argc, char *argv[])
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *all_devs = NULL;
    pcap_t *handle = NULL;
    int ret;

    /* Set console to UTF-8 output (Windows) */
    #ifdef _WIN32
        SetConsoleCP(CP_UTF8);
        SetConsoleOutputCP(CP_UTF8);
        setvbuf(stdout, NULL, _IONBF, 0);
    #endif

    printf("========================================\n");
    printf("   NPcap IP Data Packet Capture Tool\n");
    printf("========================================\n");

    /* Register signal handler */
    signal(SIGINT, signal_handler);

    /* Get device list */
    all_devs = list_devices();
    if (all_devs == NULL) {
        fprintf(stderr, "[ERROR] Failed to get network device list\n");
        return 1;
    }

    /* Select and open device */
    handle = select_and_open_device(all_devs, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "[ERROR] Failed to open network device: %s\n", errbuf);
        pcap_freealldevs(all_devs);
        return 1;
    }

    g_handle = handle;

    /* Set filter: capture only IP packets (optional) */
    struct bpf_program fp;
    char filter_exp[] = "ip";
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "[WARNING] Filter compilation failed: %s\n", pcap_geterr(handle));
    } else if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "[WARNING] Filter setup failed: %s\n", pcap_geterr(handle));
    } else {
        printf("[SUCCESS] IP packet filter set\n");
    }

    printf("\n[INFO] Starting packet capture... (Press Ctrl+C to stop)\n");

    /* Start packet capture */
    ret = pcap_loop(handle, -1, packet_callback, NULL);

    if (ret == -1) {
        fprintf(stderr, "[ERROR] pcap_loop failed: %s\n", pcap_geterr(handle));
    } else if (ret == -2) {
        printf("\n[INFO] Packet capture stopped\n");
    }

    printf("========================================\n");

    /* Clean up resources */
    if (handle != NULL) {
        pcap_close(handle);
    }
    if (all_devs != NULL) {
        pcap_freealldevs(all_devs);
    }

    printf("[INFO] Program exited\n");
    return 0;
}
