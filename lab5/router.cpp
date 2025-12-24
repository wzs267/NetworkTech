#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <Winsock2.h>
#include <windows.h>
#include "pcap.h"
#include "stdio.h"
#include <string.h>
#include "router.h"

#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib, "packet.lib")
#pragma comment(lib,"wpcap.lib")
#pragma comment(lib,"wsock32.lib")
#pragma warning(disable : 4996)



char ip[10][20];
char mask[10][20];
BYTE SrcMac[6];
pcap_t* ThisHandle;

HANDLE hThread;
DWORD dwThreadId;
int n;
int Routerlog::num = 0;
Routerlog Routerlog::diary[50] = {};
FILE* Routerlog::fp = nullptr;
Routerlog LT;
BYTE broadcast[6] = { 0xff,0xff,0xff,0xff,0xff,0xff };

void SendARP(DWORD ip0, BYTE mac[])
{
	memset(mac, 0, sizeof(mac));
	ARPFrame_t ARPFrame;

	for (int i = 0; i < 6; i++)
		ARPFrame.FrameHeader.DesMAC[i] = 0xff;

	for (int i = 0; i < 6; i++)
	{
		ARPFrame.FrameHeader.SrcMAC[i] = SrcMac[i];
		ARPFrame.SendHa[i] = SrcMac[i];
	}
	ARPFrame.FrameHeader.FrameType = htons(0x0806);
	ARPFrame.HardwareType = htons(0x0001);
	ARPFrame.ProtocolType = htons(0x0800);
	ARPFrame.HLen = 6;
	ARPFrame.PLen = 4;
	ARPFrame.Operation = htons(0x0001);

	ARPFrame.SendIP = inet_addr(ip[0]);

	for (int i = 0; i < 6; i++)
	{
		ARPFrame.RecvHa[i] = 0;
	}

	ARPFrame.RecvIP = ip0;
	if (ThisHandle == nullptr)
	{
		printf("Network interface open error\n");
	}
	else
	{
		if (pcap_sendpacket(ThisHandle, (u_char*)&ARPFrame, sizeof(ARPFrame_t)) != 0)
		{

			printf("Send error\n");
			return;
		}
		else
		{

			while (1)
			{
				pcap_pkthdr* pkt_header;
				const u_char* pkt_data;
				int rtn = pcap_next_ex(ThisHandle, &pkt_header, &pkt_data);

				if (rtn == 1)
				{
					ARPFrame_t* IPPacket = (ARPFrame_t*)pkt_data;
					if (ntohs(IPPacket->FrameHeader.FrameType) == 0x0806)
					{
						if (ntohs(IPPacket->Operation) == 0x0002)
						{
							LT.WritelogARP(IPPacket);

							for (int i = 0; i < 6; i++)
								mac[i] = IPPacket->FrameHeader.SrcMAC[i];
							break;
						}
					}
				}
			}
		}
	}
}

#pragma pack(1)
class RouterItem
{
public:
	DWORD mask;
	DWORD net;
	DWORD nextip;
	BYTE nextmac[6];
	int index;
	int type;
	RouterItem* nextitem;
	RouterItem()
	{
		memset(this, 0, sizeof(*this));
	}
	void PrintItem()
	{
		in_addr addr;
		printf("%d ", index);
		addr.s_addr = mask;
		char* temp = inet_ntoa(addr);
		printf("%s\t", temp);
		addr.s_addr = net;
		temp = inet_ntoa(addr);
		printf("%s\t", temp);
		addr.s_addr = nextip;
		temp = inet_ntoa(addr);
		printf("%s\t", temp);
		printf("%d\n", type);
	}
};
#pragma pack()

#pragma pack(1)
class RouterTable
{
public:
	RouterItem* head, * tail;
	int num;
	RouterTable()
	{
		head = new RouterItem;
		tail = new RouterItem;
		head->nextitem = tail;
		num = 0;
		for (int i = 0; i < 2; i++)
		{
			RouterItem* temp = new RouterItem;
			temp->net = (inet_addr(ip[i])) & (inet_addr(mask[i]));
			temp->mask = inet_addr(mask[i]);
			temp->type = 0;
			this->RouterAdd(temp);
		}
	}
	void RouterAdd(RouterItem* a)
	{
		RouterItem* pointer;
		if (!a->type)
		{
			a->nextitem = head->nextitem;
			head->nextitem = a;
			a->type = 0;
		}
		else
		{
			for (pointer = head->nextitem; pointer != tail && pointer->nextitem != tail; pointer = pointer->nextitem)
			{
				if (a->mask < pointer->mask && a->mask >= pointer->nextitem->mask || pointer->nextitem == tail)
				{
					break;
				}
			}
			a->nextitem = pointer->nextitem;
			pointer->nextitem = a;
		}
		RouterItem* p = head->nextitem;
		for (int i = 0; p != tail; p = p->nextitem, i++)
		{
			p->index = i;
		}
		num++;
	}
	void RouterRemove(int index)
	{
		for (RouterItem* t = head; t->nextitem != tail; t = t->nextitem)
		{
			if (t->nextitem->index == index)
			{
				if (t->nextitem->type == 0)
				{
					printf("This item cannot be deleted\n");
					return;
				}
				else
				{
					t->nextitem = t->nextitem->nextitem;
					return;
				}
			}
		}
		printf("No such entry\n");
	}
	void print()
	{
		for (RouterItem* p = head->nextitem; p != tail; p = p->nextitem)
		{
			p->PrintItem();
		}
	}
	DWORD RouterFind(DWORD ip)
	{
		for (RouterItem* t = head->nextitem; t != tail; t = t->nextitem)
		{
			if ((t->mask & ip) == t->net)
			{
				return t->nextip;
			}
		}
		return -1;
	}
};
#pragma pack()

#pragma pack(1)
class ArpTable
{
public:
	DWORD ip;
	BYTE mac[6];
	static int num;
	static void InsertArp(DWORD ip, BYTE mac[6])
	{
		arptable[num].ip = ip;
		SendARP(ip, arptable[num].mac);
		memcpy(mac, arptable[num].mac, 6);
		num++;
	}
	static int FindArp(DWORD ip, BYTE mac[6])
	{
		memset(mac, 0, 6);
		for (int i = 0; i < num; i++)
		{
			if (ip == arptable[i].ip)
			{
				memcpy(mac, arptable[i].mac, 6);
				return 1;
			}
		}
		return 0;
	}
}arptable[50];
#pragma pack()

int ArpTable::num = 0;

bool Compare(BYTE a[6], BYTE b[6])
{
	for (int i = 0; i < 6; i++)
	{
		if (a[i] != b[i])
		{
			return 0;
		}
	}
	return 1;
}

bool CheckSum(Data_t* temp)
{
	unsigned int sum = 0;
	WORD* t = (WORD*)&temp->IPHeader;
	for (int i = 0; i < sizeof(IPHeader_t) / 2; i++)
	{
		sum += t[i];
		while (sum >= 0x10000)
		{
			int s = sum >> 16;
			sum -= 0x10000;
			sum += s;
		}
	}
	if (sum == 65535)
	{
		return 1;
	}
	else
	{
		return 0;
	}
}

void SetCheckSum(Data_t* temp)
{
	temp->IPHeader.Checksum = 0;
	unsigned int sum = 0;
	WORD* t = (WORD*)&temp->IPHeader;
	for (int i = 0; i < sizeof(IPHeader_t) / 2; i++)
	{
		sum += t[i];
		while (sum >= 0x10000)
		{
			int s = sum >> 16;
			sum -= 0x10000;
			sum += s;
		}
	}
	temp->IPHeader.Checksum = ~sum;
}

void resend(ICMP_t data, BYTE desmac[])
{
	printf("Original Src MAC:\t");
	for (int i = 0; i < 6; i++)
		printf("%02x:", data.FrameHeader.SrcMAC[i]);
	printf("\n");
	printf("Original Dst MAC:\t");
	for (int i = 0; i < 6; i++)
		printf("%02x:", data.FrameHeader.DesMAC[i]);
	printf("\n");
	Data_t* temp = (Data_t*)&data;
	memcpy(temp->FrameHeader.SrcMAC, temp->FrameHeader.DesMAC, 6);
	memcpy(temp->FrameHeader.DesMAC, desmac, 6);

	printf("Modified Src MAC:\t");
	for (int i = 0; i < 6; i++)
		printf("%02x:", temp->FrameHeader.SrcMAC[i]);
	printf("\n");

	printf("Modified Dst MAC:\t");
	for (int i = 0; i < 6; i++)
		printf("%02x:", temp->FrameHeader.DesMAC[i]);
	printf("\n");


	temp->IPHeader.TTL -= 1;
	if (temp->IPHeader.TTL < 0)
	{
		return;
	}
	SetCheckSum(temp);
	int rtn = pcap_sendpacket(ThisHandle, (const u_char*)temp, 74);
	if (rtn == 0)
	{
		LT.WritelogIP("转发", temp);
	}
}


DWORD WINAPI Thread(LPVOID lparam)
{
	RouterTable RT = *(RouterTable*)(LPVOID)lparam;
	while (1)
	{
		pcap_pkthdr* pkt_header;
		const u_char* pkt_data;
		while (1)
		{
			int rtn = pcap_next_ex(ThisHandle, &pkt_header, &pkt_data);
			if (rtn)
			{
				break;
			}
		}
		FrameHeader_t* header = (FrameHeader_t*)pkt_data;
		if (Compare(header->DesMAC, SrcMac))
		{
			if (ntohs(header->FrameType) == 0x0806)
			{

			}
			else if (ntohs(header->FrameType) == 0x0800)
			{
				Data_t* data = (Data_t*)pkt_data;
				LT.WritelogIP("接收", data);
				DWORD dstip = data->IPHeader.DstIP;
				DWORD IFip = RT.RouterFind(dstip);
				if (IFip == -1)
				{
					continue;
				}
				if (CheckSum(data))
				{
					if (data->IPHeader.DstIP != inet_addr(ip[0]) && data->IPHeader.DstIP != inet_addr(ip[1]))
					{
						int t1 = Compare(data->FrameHeader.DesMAC, broadcast);
						int t2 = Compare(data->FrameHeader.SrcMAC, broadcast);
						if (!t1 && !t2)
						{

							ICMP_t* temp_ = (ICMP_t*)pkt_data;
							ICMP_t temp = *temp_;
							BYTE mac[6];
							if (IFip == 0)
							{

								if (!ArpTable::FindArp(dstip, mac))
								{
									ArpTable::InsertArp(dstip, mac);
								}
								resend(temp, mac);
							}

							else if (IFip != -1)
							{
								if (!ArpTable::FindArp(IFip, mac))
								{
									ArpTable::InsertArp(IFip, mac);
								}
								resend(temp, mac);
							}
						}
					}
				}
			}
		}
	}
}


int main()
{
	pcap_if_t* alldevs;
	pcap_if_t* d;
	char errbuf[PCAP_ERRBUF_SIZE];
	int num = 0;

	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING,
		NULL,
		&alldevs,
		errbuf
	) == -1)
	{

		printf("Error getting local devices: ");
		printf("%s\n", errbuf);
		pcap_freealldevs(alldevs);
		return 0;
	}
	int t = 0;

	for (d = alldevs; d != NULL; d = d->next)
	{
		num++;
		printf("%d:", num);
		printf("%s\n", d->name);
		if (d->description != NULL)
		{
			printf("%s\n", d->description);
		}
		else
		{
			printf("No description\n");
		}

		pcap_addr_t* a;
		for (a = d->addresses; a != NULL; a = a->next)
		{
			switch (a->addr->sa_family)
			{
			case AF_INET:
				printf("Address Family Name:AF_INET\t");
				if (a->addr != NULL)
				{

					printf("%s\t%s\n", "IP_Address:", inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr));
					printf("%s\t%s\n", "MASK_Address:", inet_ntoa(((struct sockaddr_in*)a->netmask)->sin_addr));
					strcpy(ip[t], inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr));
					strcpy(mask[t], inet_ntoa(((struct sockaddr_in*)a->netmask)->sin_addr));

				}
				break;
			case AF_INET6:
				printf("Address Family Name:AF_INET6\n");
				break;
			default:
				break;
			}
			t++;
		}
		printf("----------------------------------------------------------------------------------------------------------\n");
	}
	if (num == 0)
	{
		printf("No available interfaces\n");
		return 0;
	}
	printf("Please enter the network interface number to open");
	printf(" (1~");
	printf("%d", num);
	printf("):\n");
	num = 0;
	scanf("%d", &n);

	for (d = alldevs; num < (n - 1); num++)
	{
		d = d->next;
	}

	ThisHandle = pcap_open(d->name,
		65536,
		PCAP_OPENFLAG_PROMISCUOUS,
		1000,
		NULL,
		errbuf
	);
	if (ThisHandle == NULL)
	{
		printf("Error: Unable to open device\n");
		pcap_freealldevs(alldevs);
		return 0;
	}
	else
	{
		printf("Listening: %s\n", d->description);
		pcap_freealldevs(alldevs);
	}

	for (int i = 0; i < 2; i++)
	{
		printf("%s\t", ip[i]);
		printf("%s\n", mask[i]);
	}



	memset(SrcMac, 0, sizeof(SrcMac));

	ARPFrame_t ARPFrame;

	for (int i = 0; i < 6; i++)
	{
		ARPFrame.FrameHeader.DesMAC[i] = 0xff;
	}

	for (int i = 0; i < 6; i++)
	{
		ARPFrame.FrameHeader.SrcMAC[i] = 0x0f;
	}
	ARPFrame.FrameHeader.FrameType = htons(0x0806);
	ARPFrame.HardwareType = htons(0x0001);
	ARPFrame.ProtocolType = htons(0x0800);
	ARPFrame.HLen = 6;
	ARPFrame.PLen = 4;
	ARPFrame.Operation = htons(0x0001);
	for (int i = 0; i < 6; i++)
	{
		ARPFrame.SendHa[i] = 0x0f;
	}
	ARPFrame.SendIP = inet_addr("1.2.3.4");

	for (int i = 0; i < 6; i++)
	{
		ARPFrame.RecvHa[i] = 0x00;
	}

	ARPFrame.RecvIP = inet_addr(ip[0]);

	if (pcap_sendpacket(ThisHandle, (u_char*)&ARPFrame, sizeof(ARPFrame_t)) != 0)
	{
		printf("Send failed, exiting program\n");
		return -1;
	}

	ARPFrame_t* IPPacket;

	while (1)
	{
		pcap_pkthdr* pkt_header;
		const u_char* pkt_data;
		int rtn = pcap_next_ex(ThisHandle, &pkt_header, &pkt_data);
		if (rtn == 1)
		{
			IPPacket = (ARPFrame_t*)pkt_data;
			for (int i = 0; i < 6; i++)
			{
				SrcMac[i] = IPPacket->FrameHeader.SrcMAC[i];
			}
			if ((ntohs(IPPacket->FrameHeader.FrameType) == 0x0806) && (ntohs(IPPacket->Operation) == 0x0002))
			{
				LT.WritelogARP(IPPacket);
				printf("MAC Address:\n");
				printf("%02x:%02x:%02x:%02x:%02x:%02x\n",
					IPPacket->FrameHeader.SrcMAC[0],
					IPPacket->FrameHeader.SrcMAC[1],
					IPPacket->FrameHeader.SrcMAC[2],
					IPPacket->FrameHeader.SrcMAC[3],
					IPPacket->FrameHeader.SrcMAC[4],
					IPPacket->FrameHeader.SrcMAC[5]
				);
				break;
			}
		}
	}
	RouterTable RT;
	hThread = CreateThread(NULL, NULL, Thread, LPVOID(&RT), 0, &dwThreadId);
	int op;
	while (1)
	{
		printf("Please select an operation: ");
		printf("1: Print routing table; 2: Add route; 3: Delete route; 0: Exit\n");
		scanf("%d", &op);
		if (op == 1)
		{
			RT.print();
		}
		else if (op == 2)
		{
			RouterItem ri;
			char temp[30];
			printf("Enter destination network: ");
			scanf("%s", &temp);
			ri.net = inet_addr(temp);
			printf("Enter netmask: ");
			scanf("%s", &temp);
			ri.mask = inet_addr(temp);
			printf("Enter next hop address: ");
			scanf("%s", &temp);
			ri.nextip = inet_addr(temp);
			ri.type = 1;
			RT.RouterAdd(&ri);
		}
		else if (op == 3)
		{
			printf("Enter route index to delete: ");
			int index;
			scanf("%d", &index);
			RT.RouterRemove(index);
		}
		else if (op == 0)
		{
			break;
		}
		else
		{
			printf("Invalid operation, please try again\n");
		}
	}

	pcap_close(ThisHandle);
	return 0;
}