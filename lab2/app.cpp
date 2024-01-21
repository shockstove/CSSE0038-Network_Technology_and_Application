#define  _CRT_SECURE_NO_WARNINGS 1
#include<pcap.h>
#include<Winsock2.h>
#include<iostream>
#include<stdio.h>
#include<stdlib.h>
#pragma comment(lib,"Packet.lib")
#pragma comment(lib,"wpcap.lib")
#pragma comment(lib,"ws2_32.lib")//表示链接的时侯找ws2_32.lib
//#pragma warning( disable : 4996 )//要使用旧函数
using namespace std;

/* 4 bytes IP address */
typedef struct ip_address {
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
}ip_address;

typedef struct ehter_header {
    u_char    ether_dhost[6];   //目的MAC地址
    u_char    ether_shost[6];   //源MAC地址
    u_short   ether_type;       //帧类型
}ether_header;

/* IPv4 header */
typedef struct ip_header {
    u_char  ver_ihl; // Version (4 bits) + IP header length (4 bits)
    u_char  tos;     // Type of service 
    u_short tlen;    // Total length 
    u_short identification; // Identification
    u_short flags_fo; // Flags (3 bits) + Fragment offset (13 bits)
    u_char  ttl;      // Time to live
    u_char  proto;    // Protocol 
    u_short crc;      // Header checksum
    ip_address  saddr; // Source address
    ip_address  daddr; // Destination address
    u_int  op_pad;     // Option + Padding
}ip_header;

//报文处理函数
void packet_handler(
    u_char* param,
    const struct pcap_pkthdr* header,
    const u_char* pkt_data);

int main()
{
    pcap_if_t* alldevs;
    pcap_if_t* d;
    int inum;
    int i = 0;
    pcap_t* adhandle;
    char errbuf[PCAP_ERRBUF_SIZE];
    //获取设备列表
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING,
        NULL, &alldevs, errbuf) == -1)
    {
        fprintf(stderr, "在检测设备时出现错误: %s\n", errbuf);
        exit(1);
    }
    //打印列表
    for (d = alldevs; d; d = d->next)
    {
        printf("%d. %s", ++i, d->name);
        if (d->description)
            printf(" (%s)\n", d->description);
        else
            printf(" 无可用设备！\n");
    }
    if (i == 0)
        return -1;
    printf("请输入设备编号 (1-%d):", i);
    scanf("%d", &inum);
    if (inum < 1 || inum > i)
    {
        printf("\n超出可用范围\n");
        pcap_freealldevs(alldevs);
        return -1;
    }

    //跳转至想要监听的设备
    for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);
    //打开设备
    if ((adhandle = pcap_open(d->name, // name of the device
        65536, // portion of the packet to capture
               // 65536 guarantees that the whole packet will
               // be captured on all the link layers
        PCAP_OPENFLAG_PROMISCUOUS, // promiscuous mode
        1000, // read timeout
        NULL, // authentication on the remote machine
        errbuf // error buffer
    )) == NULL)
    {
        fprintf(stderr,
            "\n%s设备不支持！%\n",
            d->name);
        pcap_freealldevs(alldevs);
        return -1;
    }
    printf("\n正在 %s 上监听...\n", d->description);
    cout << "正在设置过滤条件..."<<endl;
    char filter[40] = "";
    u_int netmask;
    struct bpf_program fcode;
    getchar();
    scanf("%[^\n]", filter);
    printf("输入要捕获的个数：");
    int count = 1;
    scanf("%d", &count);
    if (d->addresses != NULL)
        //获取掩码
        netmask = ((struct sockaddr_in*)(d->addresses->netmask))->sin_addr.S_un.S_addr;
    else
        //C类设备
        netmask = 0xffffff;
    if (pcap_compile(adhandle, &fcode, filter, 1, netmask) < 0)
    {
        fprintf(stderr,"\n无法解析过滤器，请检查输入\n");
        pcap_freealldevs(alldevs);
        return -1;
    }
    else
    {
        if (pcap_setfilter(adhandle, &fcode) < 0)
        {
            cout << "过滤器发生错误！\n" << endl;
            return -1;
        }
        cout << "正在监听" << d->description << endl;
        pcap_freealldevs(alldevs);
        pcap_loop(adhandle, count, packet_handler, NULL);
    }
    return 0;
}


void  packet_handler(u_char* param,
    const struct pcap_pkthdr* header,
    const u_char* pkt_data)
{
    ip_header* ih;
    u_short check_sum;
    u_short offset;
    u_short id;
    ether_header* eh = (ether_header*)pkt_data; 
    u_short ethernet_type;

    ih = (struct ip_header*)(pkt_data + 14);
    //eh = (ether_header*)(pkt_data);
    
    ethernet_type = ntohs(eh->ether_type);
    printf("++++++++++以太帧解析+++++++++\n");
    printf("数据包类型为:%x-", ethernet_type);
    switch (ethernet_type)
    {
    case 0x0800:

        printf("IPv4协议\n");
        break;
    case 0x0806:
        printf("ARP请求应答\n");
        break;
    case 0x8035:
        printf("RARP请求应答\n");
        break;
    default:
        break;
    }
    printf("源MAC地址为：%02x:%02x:%02x:%02x:%02x:%02x\n", eh->ether_shost[0], eh->ether_shost[1], eh->ether_shost[2], eh->ether_shost[3], eh->ether_shost[4], eh->ether_shost[5]);
    printf("目标MAC地址为：%02x:%02x:%02x:%02x:%02x:%02x\n", eh->ether_dhost[0], eh->ether_dhost[1], eh->ether_dhost[2], eh->ether_dhost[3], eh->ether_dhost[4], eh->ether_dhost[5]);

    if (ethernet_type != 0x0800)
    {
        cout << "非IPv4报文，退出解析\n" << endl;
        return;
    }
    //网络字节序转为主机字节序
    id = ntohs(ih->identification);
    check_sum = ntohs(ih->crc);
    offset = ntohs(ih->flags_fo);
    printf("++++++++++IP数据报解析+++++++++\n");
    printf("IP Version :%d\n", ih->ver_ihl >> 4);
    printf("首部长度：%d\n", (ih->ver_ihl & 0xF)*4);
    printf("服务类型：%d\n", ih->tos);
    printf("总长度：%d\n", ih->tlen);
    printf("标识：0x%x\n",id);
    printf("标志：0x%x\n", offset >> 13);
    printf("片偏移：%d\n",offset&0x1fff);
    printf("生存时间：%d\n",ih->ttl);
    printf("头部校验和：0x%x\n",check_sum);
    printf("源IP地址：%d.%d.%d.%d\n",ih->saddr.byte1,ih->saddr.byte2,ih->saddr.byte3,ih->saddr.byte4);
    printf("目标IP地址：%d.%d.%d.%d\n",ih->daddr.byte1,ih->daddr.byte2,ih->daddr.byte3,ih->daddr.byte4);
    printf("协议类型：%d-", ih->proto);
    switch (ih->proto)
    {
    case 1:
        printf("ICMP\n");
        break;
    case 2:
        printf("IGMP\n");
        break;
    case 6:
        printf("TCP\n");
        break;
    case 17:
        printf("UDP\n");
        break;
    case 41:
        printf("IPv6\n");
        break;
    default:
        break;
    }
    printf("++++++++++本次解析完成+++++++++\n\n");
    return;
}