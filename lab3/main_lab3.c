// main_lab3.c - simple CLI to send ARP and capture reply
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include "arp_sender.h"
#include "arp_parser.h"

#pragma comment(lib, "iphlpapi.lib")

// helper: parse dotted IPv4 string to 4-byte array
int parse_ipv4(const char *s, uint8_t out[4]) {
    // Use inet_addr for MinGW compatibility
    unsigned long a = inet_addr(s); // returns INADDR_NONE on failure
    if (a == INADDR_NONE) return 0;
    // inet_addr returns address in network byte order
    memcpy(out, &a, 4);
    return 1;
}

// try to get adapter MAC by matching GUID in pcap device name
int get_mac_by_pcap_name(const char *pcap_name, uint8_t mac[6]) {
    // pcap_name contains something like "\\Device\\NPF_{GUID}"
    const char *l = strchr(pcap_name, '{');
    const char *r = strchr(pcap_name, '}');
    if (!l || !r || r <= l) return 0;
    char guid[64];
    int len = (int)(r - l - 1);
    if (len <= 0 || len >= (int)sizeof(guid)) return 0;
    memcpy(guid, l+1, len);
    guid[len] = '\0';

    ULONG flags = GAA_FLAG_INCLUDE_PREFIX;
    ULONG family = AF_UNSPEC;
    ULONG outBufLen = 15000;
    PIP_ADAPTER_ADDRESSES pAddresses = (PIP_ADAPTER_ADDRESSES) malloc(outBufLen);
    DWORD dwRet = GetAdaptersAddresses(family, flags, NULL, pAddresses, &outBufLen);
    if (dwRet == ERROR_BUFFER_OVERFLOW) {
        free(pAddresses);
        pAddresses = (PIP_ADAPTER_ADDRESSES) malloc(outBufLen);
        dwRet = GetAdaptersAddresses(family, flags, NULL, pAddresses, &outBufLen);
    }
    if (dwRet != NO_ERROR) {
        if (pAddresses) free(pAddresses);
        return 0;
    }

    PIP_ADAPTER_ADDRESSES p = pAddresses;
    for (; p; p = p->Next) {
        if (p->AdapterName && strstr(p->AdapterName, guid)) {
            if (p->PhysicalAddressLength == 6) {
                memcpy(mac, p->PhysicalAddress, 6);
                free(pAddresses);
                return 1;
            }
        }
    }

    // fallback: first adapter with MAC
    for (p = pAddresses; p; p = p->Next) {
        if (p->PhysicalAddressLength == 6) {
            memcpy(mac, p->PhysicalAddress, 6);
            free(pAddresses);
            return 1;
        }
    }

    free(pAddresses);
    return 0;
}

int main(void) {
    pcap_if_t *alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];
    int exit_code = 0;

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        return 1;
    }

    printf("Available devices:\n");
    pcap_if_t *d;
    int i = 0, idx = -1;
    for (d = alldevs; d; d = d->next) {
        printf("%d. %s", ++i, d->name);
        if (d->description) printf(" (%s)", d->description);
        printf("\n");
    }

    printf("Select device number: ");
    if (scanf("%d", &idx) != 1 || idx < 1 || idx > i) {
        fprintf(stderr, "Invalid selection\n");
        pcap_freealldevs(alldevs);
        return 1;
    }

    d = alldevs;
    for (i = 1; i < idx; i++) d = d->next;

    pcap_t *handle = pcap_open_live(d->name, 65536, 1, 1000, errbuf);
    if (!handle) {
        fprintf(stderr, "pcap_open_live failed: %s\n", errbuf);
        pcap_freealldevs(alldevs);
        return 1;
    }

    // set BPF filter to only capture ARP packets (reduces noise)
    struct bpf_program fp;
    char filter_exp[128];
    snprintf(filter_exp, sizeof(filter_exp), "arp");
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == 0) {
        pcap_setfilter(handle, &fp);
    } else {
        fprintf(stderr, "[WARN] Failed to compile BPF filter\n");
    }

    uint8_t src_mac[6] = {0};
    if (!get_mac_by_pcap_name(d->name, src_mac)) {
        fprintf(stderr, "Warning: failed to get adapter MAC, using zeros\n");
    } else {
        printf("Using source MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
               src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5]);
    }

    char ipstr[64];
    printf("Enter IPv4 address to query (e.g. 192.168.1.10): ");
    scanf("%63s", ipstr);
    uint8_t target_ip[4];
    if (!parse_ipv4(ipstr, target_ip)) {
        fprintf(stderr, "Invalid IPv4 address\n");
        pcap_close(handle);
        pcap_freealldevs(alldevs);
        return 1;
    }

    // Determine source IP to put into ARP sender: try to pick first unicast IPv4 of adapter
    ULONG flags = GAA_FLAG_INCLUDE_PREFIX;
    ULONG family = AF_UNSPEC;
    ULONG outBufLen = 15000;
    PIP_ADAPTER_ADDRESSES pAddresses = (PIP_ADAPTER_ADDRESSES) malloc(outBufLen);
    DWORD dwRet = GetAdaptersAddresses(family, flags, NULL, pAddresses, &outBufLen);
    if (dwRet == ERROR_BUFFER_OVERFLOW) {
        free(pAddresses);
        pAddresses = (PIP_ADAPTER_ADDRESSES) malloc(outBufLen);
        dwRet = GetAdaptersAddresses(family, flags, NULL, pAddresses, &outBufLen);
    }
    uint8_t src_ip[4] = {0};
    if (dwRet == NO_ERROR) {
        PIP_ADAPTER_ADDRESSES p = pAddresses;
        for (; p; p = p->Next) {
            if (p->AdapterName && strstr(d->name, p->AdapterName)) {
                PIP_ADAPTER_UNICAST_ADDRESS ua = p->FirstUnicastAddress;
                for (; ua; ua = ua->Next) {
                    if (ua->Address.lpSockaddr->sa_family == AF_INET) {
                        struct sockaddr_in *sa = (struct sockaddr_in *)ua->Address.lpSockaddr;
                        memcpy(src_ip, &sa->sin_addr.s_addr, 4);
                        break;
                    }
                }
                break;
            }
        }
        if (src_ip[0]==0) {
            // fallback: first IPv4 found
            for (p = pAddresses; p; p = p->Next) {
                PIP_ADAPTER_UNICAST_ADDRESS ua = p->FirstUnicastAddress;
                for (; ua; ua = ua->Next) {
                    if (ua->Address.lpSockaddr->sa_family == AF_INET) {
                        struct sockaddr_in *sa = (struct sockaddr_in *)ua->Address.lpSockaddr;
                        memcpy(src_ip, &sa->sin_addr.s_addr, 4);
                        break;
                    }
                }
                if (src_ip[0]!=0) break;
            }
        }
    }
    if (pAddresses) free(pAddresses);

    if (src_ip[0]==0) {
        fprintf(stderr, "Warning: failed to determine source IP, using 0.0.0.0\n");
    } else {
        printf("Using source IP: %u.%u.%u.%u\n", src_ip[0], src_ip[1], src_ip[2], src_ip[3]);
    }

    // send ARP request
    if (send_arp_request(handle, src_mac, src_ip, target_ip) != 0) {
        fprintf(stderr, "Failed to send ARP request\n");
    } else {
        printf("ARP request sent, waiting for reply (2s)...\n");
    }

    // Try Windows SendARP as a fast fallback to read local ARP cache / prompt kernel to resolve
    DWORD macAddrLen = 6;
    BYTE macAddr[6];
    ULONG destIp = 0;
    memcpy(&destIp, target_ip, 4);
    // SendARP expects destination in network byte order (inet_addr gives network order)
    DWORD sendArpResult = SendARP(destIp, 0, (PULONG)macAddr, &macAddrLen);
    if (sendArpResult == NO_ERROR && macAddrLen >= 6) {
        printf("SendARP result: %u.%u.%u.%u => %02X:%02X:%02X:%02X:%02X:%02X\n",
               target_ip[0], target_ip[1], target_ip[2], target_ip[3],
               macAddr[0], macAddr[1], macAddr[2], macAddr[3], macAddr[4], macAddr[5]);
        // mark found and proceed to cleanup + pause
        // found variable will be handled below
        // copy to sender_mac for consistency
        // fall through to capture loop for unified cleanup
        // we set found to 1 to avoid printing 'No ARP reply' later
        // Note: do not return immediately so user can see result
        // (we'll clean up and pause at the end)
        // print already done above
        // set a flag by storing mac into sender_mac and setting found
        // We'll reuse the found variable below; to keep scope, set a local marker
        // Use a small hack: print done and continue; final cleanup will pause.
        // To indicate success, set exit_code = 0 and skip waiting for pcap if desired.
        // Here we simply skip waiting by jumping to done label.
        // Prepare a quick cleanup
        pcap_close(handle);
        pcap_freealldevs(alldevs);
        // flush stdin leftover (from previous scanf)
        int ch;
        while ((ch = getchar()) != '\n' && ch != EOF) {}
        printf("Press Enter to exit..."); fflush(stdout);
        getchar();
        return 0;
    }

    // capture loop with timeout of ~2000ms
    struct pcap_pkthdr header;
    const u_char *pkt_data;
    int found = 0;
    int tries = 0;
    // try several timeouts (pcap_next will return NULL on timeout)
    while (tries < 6) {
        pkt_data = pcap_next(handle, &header);
        if (!pkt_data) {
            tries++;
            continue;
        }
        uint8_t sender_mac[6];
        uint8_t sender_ip[4];
        // Debug: print first bytes of packet (ethertype)
        if (header.len >= 14) {
            uint16_t ethertype = (pkt_data[12] << 8) | pkt_data[13];
            // printf("[DEBUG] Got packet, ethertype=0x%04X, len=%u\n", ethertype, header.len);
        }
        if (parse_arp_packet(pkt_data, header.len, sender_mac, sender_ip)) {
            // check sender_ip matches target_ip
            if (memcmp(sender_ip, target_ip, 4) == 0) {
                printf("Found: %u.%u.%u.%u => %02X:%02X:%02X:%02X:%02X:%02X\n",
                       sender_ip[0], sender_ip[1], sender_ip[2], sender_ip[3],
                       sender_mac[0], sender_mac[1], sender_mac[2], sender_mac[3], sender_mac[4], sender_mac[5]);
                found = 1;
                break;
            }
        }
    }

    if (!found) printf("No ARP reply received for %s\n", ipstr);

    pcap_close(handle);
    pcap_freealldevs(alldevs);
    // flush stdin leftover (from previous scanf)
    int ch;
    while ((ch = getchar()) != '\n' && ch != EOF) {}
    printf("Press Enter to exit..."); fflush(stdout);
    getchar();
    return exit_code;
}
