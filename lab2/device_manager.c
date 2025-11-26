/*
 * device_manager.c
 * Network device management module implementation
 */

#include "device_manager.h"
#include "packet_structures.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * List all network devices in the system
 */
pcap_if_t *list_devices(void)
{
    pcap_if_t *all_devs = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];

    /* Get device list */
    if (pcap_findalldevs(&all_devs, errbuf) == -1) {
        fprintf(stderr, "[ERROR] Failed to get device list: %s\n", errbuf);
        return NULL;
    }

    if (all_devs == NULL) {
        fprintf(stderr, "[ERROR] No network device found\n");
        return NULL;
    }

    return all_devs;
}

/*
 * Select a device from the list and open it
 */
pcap_t *select_and_open_device(pcap_if_t *all_devs, char *errbuf)
{
    pcap_if_t *d;
    int inum = 0;
    int i = 0;

    /* List all devices */
    printf("\n========== Available Network Devices ==========\n");
    for (d = all_devs; d != NULL; d = d->next) {
        printf("%d. %s", ++i, d->name);
        if (d->description) {
            printf(" (%s)", d->description);
        }
        printf("\n");
    }
    printf("==============================================\n\n");

    if (i == 0) {
        fprintf(stderr, "[ERROR] No network device found\n");
        return NULL;
    }

    /* Prompt user to select device */
    printf("Please select a device (1-%d): ", i);
    if (scanf("%d", &inum) != 1 || inum < 1 || inum > i) {
        fprintf(stderr, "[ERROR] Invalid selection\n");
        return NULL;
    }

    /* Jump to selected device */
    for (d = all_devs, i = 0; i < inum - 1; d = d->next, i++);

    /* Open device */
    printf("\n[INFO] Opening device: %s\n", d->name);

    pcap_t *handle = pcap_open_live(d->name, SNAPLEN, 1, READ_TIMEOUT, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "[ERROR] Failed to open device: %s\n", errbuf);
        return NULL;
    }

    printf("[SUCCESS] Device opened\n");
    return handle;
}
