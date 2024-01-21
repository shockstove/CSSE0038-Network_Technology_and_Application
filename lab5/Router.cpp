#define  _CRT_SECURE_NO_WARNINGS 1
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include<vector>
#include<pcap.h>
#include<Winsock2.h>
#include<iostream>
#include<stdio.h>
#include<windows.h>
#include<iphlpapi.h>
#include<algorithm>
#pragma comment(lib,"Packet.lib")
#pragma comment(lib,"wpcap.lib")
#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"iphlpapi.lib")//表示链接的时侯找ws2_32.lib
//#pragma warning( disable : 4996 )//要使用旧函数
using namespace std;

PIP_ADAPTER_ADDRESSES pAddresses;   

pcap_t* adhandle;     
pcap_if_t* d;
struct pcap_pkthdr* pkt_header;     
const u_char* pkt_data;             
u_char dev_mac[6];

HANDLE hThread;
DWORD dwThreadId;

u_long dev_ip[2][10];
FILE* fp = nullptr;
time_t rawtime;
struct tm* ptminfo;

#define FLAG_DIR 1<<0

#pragma pack(1)
/* 4 bytes IP address */
typedef struct ip_address {
    u_long ip;
}ip_address;

/*以太帧头部 */
typedef struct ehter_header {
    u_char    ether_dhost[6];   //目的MAC地址
    u_char    ether_shost[6];   //源MAC地址
    u_short   ether_type;       //帧类型
}ether_header;

/*ARP帧*/
typedef struct ARP_frame {
    ether_header header;    //以太帧首部
    u_short hardware;       //硬件类型
    u_short protocol;       //协议类型
    u_char hardware_size;   //硬件地址长度
    u_char protocol_size;   //协议地址长度
    u_short opcode;         //操作码
    u_char sender_mac[6];   //源MAC地址
    ip_address sender_ip;   //源IP地址
    u_char target_mac[6];   //目的MAC地址
    ip_address target_ip;   //目的IP地址
}ARP_frame;

/*IPv4头部*/
typedef struct ip_header {
    u_char  ver_ihl; // 版本号(4 bits) + 首部长度(4 bits)
    u_char  tos;     // 服务类型
    u_short tlen;    // 总长度
    u_short identification; // 标识
    u_short flags_fo; // 标志(3 bits) + 片偏移(13 bits)
    u_char  ttl;      // 生存时间
    u_char  proto;    // 协议类型 
    u_short crc;      // 头部校验和
    ip_address  saddr; // 源IP地址
    ip_address  daddr; // 目的IP地址
}ip_header;

/*ICMP报文*/
typedef struct icmp_header {
    u_char type;
    u_char code;
    u_short crc;
    u_short identification;
    u_short seq;
}icmp_header;


/*数据包*/
typedef struct data_packet {
    ether_header etherHeader;
    ip_header ipHeader;
}data_packet;

#pragma pack(0)

void print_ip(u_long ip) {
    printf("%d.%d.%d.%d", (u_char)ip, (ip & 0xFF00) >> 8, (ip & 0xFF0000) >> 16, (ip & 0xFF000000) >> 24);
    return;
}
void print_mac(u_char m[]) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x",m[0],m[1],m[2],m[3],m[4],m[5]);
    return;
}

void write_packet(FILE* fp, data_packet* data, bool type) {
    if (type == 1)
        fprintf(fp, "[%02d:%02d:%02d][发送]:", ptminfo->tm_hour, ptminfo->tm_min, ptminfo->tm_sec);
    else
        fprintf(fp, "[%02d:%02d:%02d][接收]:", ptminfo->tm_hour, ptminfo->tm_min, ptminfo->tm_sec);


    u_short ethernet_type = ntohs(data->etherHeader.ether_type);
    if (ethernet_type == 0x0800) {
        in_addr addr;
        addr.s_addr = data->ipHeader.saddr.ip;
        char* temp = inet_ntoa(addr);
        fprintf(fp, "sourceIP:%s\t", temp);
        addr.s_addr = data->ipHeader.daddr.ip;
        temp = inet_ntoa(addr);
        fprintf(fp, "targetIP:%s\n", temp);
        u_char* m = data->etherHeader.ether_shost;
        fprintf(fp, "                sourceMAC:%02x:%02x:%02x:%02x:%02x:%02x\t", m[0], m[1], m[2], m[3], m[4], m[5]);
        m = data->etherHeader.ether_shost;
        fprintf(fp, "targetMAC:%02x:%02x:%02x:%02x:%02x:%02x\n", m[0], m[1], m[2], m[3], m[4], m[5]);
        fprintf(fp, "++++++++++++++++++++IP数据报++++++++++++++++++++\n");
        fprintf(fp, "IP version:%d\n", data->ipHeader.ver_ihl >> 4);
        fprintf(fp, "首部长度:%d\n", (data->ipHeader.ver_ihl & 0xF) * 4);
        fprintf(fp, "服务类型%d\n", data->ipHeader.tos);
        fprintf(fp, "总长度:%d\n", data->ipHeader.tlen);
        fprintf(fp, "标识:0x%x\n", ntohs(data->ipHeader.identification));
        fprintf(fp, "标志:0x%x\n", ntohs(data->ipHeader.flags_fo) >> 13);
        fprintf(fp, "片偏移:%d\n", ntohs(data->ipHeader.flags_fo) & 0x1FFF);
        fprintf(fp, "ttl:%d\n", data->ipHeader.ttl);
        fprintf(fp, "头部校验和:0x%x\n", ntohs(data->ipHeader.crc));
        switch (data->ipHeader.proto) {
        case 1:
            fprintf(fp, "协议类型:ICMP\n");
            fprintf(fp, "          +++++++++++++++ICMP+++++++++++++++\n");
            icmp_header* icmpHeader = (icmp_header*)(data + 34);
            switch (ntohs(icmpHeader->type)) {
            case 0:
                if (ntohs(icmpHeader->code) == 0) {
                    fprintf(fp, "类型:Ping应答\n");
                }
                break;
            case 8:
                if (ntohs(icmpHeader->code) == 0) {
                    fprintf(fp, "类型:Ping请求\n");
                }
                break;
            case 11:
                if (ntohs(icmpHeader->code) == 0) {
                    fprintf(fp, "类型:超时，(traceroute)\n");
                }
                else if (ntohs(icmpHeader->code) == 1) {
                    fprintf(fp, "类型:超时，数据包组装\n");
                }
                break;
            default:
                break;
            }
            break;
        }
        fprintf(fp, "++++++++++++++++++++解析完成++++++++++++++++++++\n\n");
    }
    else if (ethernet_type == 0x0806) {
        ARP_frame* arpPacket = (ARP_frame*)(data);
        u_char* m = data->etherHeader.ether_shost;
        fprintf(fp, "                sourceMAC:%02x:%02x:%02x:%02x:%02x:%02x\t", m[0], m[1], m[2], m[3], m[4], m[5]);
        m = data->etherHeader.ether_shost;
        fprintf(fp, "targetMAC:%02x:%02x:%02x:%02x:%02x:%02x\n", m[0], m[1], m[2], m[3], m[4], m[5]);
        fprintf(fp, "++++++++++++++++++++ARP数据报++++++++++++++++++++\n");
        fprintf(fp, "硬件类型:%d\n", ntohs(arpPacket->hardware));
        fprintf(fp, "协议类型:0x%x\n", ntohs(arpPacket->protocol));
        switch (ntohs(arpPacket->opcode)) {
        case 1:
            fprintf(fp, "操作类型:ARP请求\n");
            break;
        case 2:
            fprintf(fp, "操作类型:应答报文\n");
            break;
        }
        m = arpPacket->sender_mac;
        fprintf(fp, "sourceMAC:%02x:%02x:%02x:%02x:%02x:%02x\n", m[0], m[1], m[2], m[3], m[4], m[5]);
        in_addr addr;
        addr.s_addr = arpPacket->sender_ip.ip;
        char* temp = inet_ntoa(addr);
        fprintf(fp, "sourceIP:%s\n", temp);
        m = arpPacket->target_mac;
        fprintf(fp, "targetMAC:%02x:%02x:%02x:%02x:%02x:%02x\n", m[0], m[1], m[2], m[3], m[4], m[5]);
        addr.s_addr = arpPacket->target_ip.ip;
        temp = inet_ntoa(addr);
        fprintf(fp, "targetIP:%s\n", temp);
        fprintf(fp, "++++++++++++++++++++解析完成++++++++++++++++++++\n");
    }
}


//路由表表项
class router_table_entry {
public:
    u_long target_net;      //目的网络
    u_long mask;            //掩码
    u_long next_jump;       //下一跳地址
    u_int dev_ip_index;     //对应接口
    u_int flag;             //标记表项属性
    router_table_entry() {
        memset(this, 0, sizeof(*this));
    }
};

bool cmp(const router_table_entry& a, const router_table_entry& b) {
    if (a.target_net == b.target_net) {
        return a.mask > b.mask;
    }
    else return a.target_net > b.target_net;
}

bool not_broadcast(data_packet* data) {
    bool d = false, s = false;
    for (int i = 0; i < 6; i++) {
        if (data->etherHeader.ether_dhost[i] != 0xff) {
            d = true;
        }
        if (data->etherHeader.ether_shost[i] != 0xff) {
            s = true;
        }
    }
    return d && s;
}

void calChecksum(data_packet* pkt) {
    //计算校验和
    pkt->ipHeader.crc = 0;
    u_long sum = 0;
    u_short* pointer = (u_short*)&pkt->ipHeader;
    //对ip首部字段按16位求和
    for (int i = 0; i < 10; i++)
    {
        u_short temp = pointer[i];
        sum += temp;
    }
    //超出16位
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    //取反
    pkt->ipHeader.crc = (u_short)~sum;
}
bool checkChecksum(data_packet* pkt) {
    //检验校验和
    u_int sum = pkt->ipHeader.crc;
    pkt->ipHeader.crc = 0;
    calChecksum(pkt);
    //与原本校验和一致则通过
    if ((u_short)sum == pkt->ipHeader.crc)
        return true;
    else return false;
}
void calChecksum_icmp(icmp_header* pkt) {
    //计算校验和
    pkt->crc = 0;
    u_long sum = 0;
    u_short* pointer = (u_short*)pkt;
    //对ip首部字段按16位求和
    for (int i = 0; i < 8 / 2; i++)
    {
        u_short temp = pointer[i];
        sum += temp;
    }
    //超出16位
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    //取反
    pkt->crc = (u_short)~sum;
}

//路由表结构
class router_table {
public:
    vector<router_table_entry> routerTable;         //使用vector来存储表项
    router_table() {
    }
    //插入路由表表项
    void router_table_add(router_table_entry entry) {
        routerTable.push_back(entry);
        sort(routerTable.begin(), routerTable.end(), cmp);
        return;
    }
    //删除路由表表项
    void router_table_delete(int i) {
        if (i > routerTable.size()) {
            cout << "错误的编号" << endl;
            return;
        }
        if (routerTable[i - 1].flag & FLAG_DIR) {
            cout << "直接投递项不可删除" << endl;
            return;
        }
        routerTable.erase(routerTable.begin() + i - 1);
        return;
    }
    //打印路由表
    void print() {
        for (int i = 0; i < routerTable.size(); i++) {
            in_addr mask, tnet, devip, njump;
            router_table_entry e = routerTable[i];
            mask.s_addr = e.mask;
            tnet.s_addr = e.target_net;
            devip.s_addr = dev_ip[0][e.dev_ip_index];
            njump.s_addr = e.next_jump;
            char type = e.flag & FLAG_DIR ? 'D' : 'S';
            char* temp = inet_ntoa(tnet);
            printf("%s\t", temp);
            temp = inet_ntoa(mask);
            printf("%s\t", temp);
            temp = inet_ntoa(devip);
            printf("%s\t", temp);
            temp = inet_ntoa(njump);
            printf("%c\t%s\n", type, temp);
        }
        return;
    }
    //查找路由表
    u_long router_table_search(u_long ip) {
        for (int i = 0; i < routerTable.size(); i++) {
            if (routerTable[i].target_net == (ip & routerTable[i].mask)) {
                return routerTable[i].next_jump;
            }
        }
        return -1;
    }
};

//ARP缓存表表项
class arp_table_entry {
public:
    u_long ip;          
    u_char mac[6];
    arp_table_entry() {
        memset(this, 0, sizeof(*this));
    }
};

//ARP缓存表
class arp_table {
public:
    vector<arp_table_entry> arpTable;
    void print() {
        for (int i = 0; i < arpTable.size(); i++) {
            print_ip(arpTable[i].ip);
            printf("  ");
            print_mac(arpTable[i].mac);
            printf("\n");
        }
    }
    void arp_table_add(u_long ip) {
        arp_table_entry e;
        e.ip = ip;
        u_char temp[6];
        //构造ARP请求包
        ARP_frame ARPframe;
        ARP_frame* RecFrame;
        struct pcap_pkthdr* arppkt_header;
        const u_char* arppkt_data;
        for (int i = 0; i < 6; i++)
        {
            ARPframe.header.ether_shost[i] = dev_mac[i];
            ARPframe.header.ether_dhost[i] = 0xff;
            ARPframe.sender_mac[i] = dev_mac[i];
            ARPframe.target_mac[i] = 0x00;
        }
        strncpy((char*)&ARPframe.sender_ip.ip, (char*)(d->addresses->addr->sa_data + 2), 4);
        u_char addr = 0;
        ARPframe.target_ip.ip = ip;
        ARPframe.header.ether_type = htons(0x0806);
        ARPframe.hardware = htons(0x0001);
        ARPframe.protocol = htons(0x0800);
        ARPframe.hardware_size = 6;
        ARPframe.protocol_size = 4;
        ARPframe.opcode = htons(0x0001);//1表示请求包
        //打印和写入信息
        time(&rawtime);
        ptminfo = localtime(&rawtime);
        printf("[%02d:%02d:%02d][发送]:ARP request dest desIP=", ptminfo->tm_hour, ptminfo->tm_min, ptminfo->tm_sec);
        print_ip(ip);
        printf("\n");
        write_packet(fp, (data_packet*)&ARPframe, 1);
        //发送ARP请求
        pcap_sendpacket(adhandle, (u_char*)&ARPframe, sizeof(ARPframe));
        //循环捕获ARP应答
        while (1)
        {
            int rtn = pcap_next_ex(adhandle, &arppkt_header, &arppkt_data);
            switch (rtn)
            {
            case -1:
                cout << "捕获错误" << endl;
                break;
            case 0:
                cout << "未捕获到数据报" << endl;
                break;
            default:
                //收到了数据包
                RecFrame = (ARP_frame*)arppkt_data;
                if (ntohs(RecFrame->header.ether_type) == 0x0806) {
                    if ((ntohs(RecFrame->protocol) == 0x0800)
                        && (ntohs(RecFrame->opcode) == 0x0002)
                        && (RecFrame->target_ip.ip == ARPframe.sender_ip.ip)
                        && (RecFrame->sender_ip.ip == ARPframe.target_ip.ip)) {
                        //收到的是ARP响应包且响应包源IP是请求包目的IP，响应包目的IP是本机IP
                        //读取并保存该包中存储的源MAC地址
                        for (int i = 0; i < 6; i++) {
                            e.mac[i] = RecFrame->sender_mac[i];
                        }
                        //打印和写入信息
                        time(&rawtime);
                        ptminfo = localtime(&rawtime);
                        printf("[%02d:%02d:%02d][接收]:ARP reply desIP:", ptminfo->tm_hour, ptminfo->tm_min, ptminfo->tm_sec);
                        print_ip(ARPframe.target_ip.ip);
                        printf("  desMAC:");
                        print_mac(RecFrame->sender_mac);
                        printf("\n");
                        write_packet(fp, (data_packet*)RecFrame, 0);
                        goto FINISH;
                    }
                }
            }
        }
        FINISH:
        arpTable.push_back(e);
    }
    bool arp_table_search(u_long ip, u_char m[6]) {
        for (int i = 0; i < arpTable.size(); i++) {
            if (arpTable[i].ip == ip) {
                memcpy(m, arpTable[i].mac, 6);
                return 1;
            }
        }
        return 0;
    }

};

arp_table arpTable;
router_table routerTable;

void ICMP_packet_send(u_char type, u_char code) {
    u_char* ICMPbuf = new u_char[70];
    //构造以太帧部分
    memcpy(((ether_header*)ICMPbuf)->ether_shost, ((ehter_header*)pkt_data)->ether_dhost, 6);
    memcpy(((ether_header*)ICMPbuf)->ether_dhost, ((ehter_header*)pkt_data)->ether_shost, 6);
    ((ether_header*)ICMPbuf)->ether_type = htons(0x0800);
    //构造IP数据包部分
    ip_header* icmp_ip_header = (ip_header*)(ICMPbuf + 14);
    ip_header* pkt_ip_header = (ip_header*)(pkt_data + 14);
    icmp_ip_header->ver_ihl = pkt_ip_header->ver_ihl;
    icmp_ip_header->tos = pkt_ip_header->tos;
    icmp_ip_header->tlen = htons(56);
    icmp_ip_header->flags_fo = pkt_ip_header->flags_fo;
    icmp_ip_header->ttl = 64;       //TTL更新为64
    icmp_ip_header->proto = 1;
    icmp_ip_header->saddr.ip = dev_ip[0][1];
    icmp_ip_header->daddr = pkt_ip_header->saddr;
    calChecksum((data_packet*)ICMPbuf);
    //构造ICMP部分
    icmp_header* icmp_icmp_header = (icmp_header*)(ICMPbuf + 34);
    icmp_icmp_header->type = type;
    icmp_icmp_header->code = code;
    icmp_icmp_header->identification = 0;
    icmp_icmp_header->seq = 0;
    calChecksum_icmp(icmp_icmp_header);
    //超时报告报文数据部分为发生差错的IP数据包首部和数据区的8个字节
    memcpy((u_char*)(ICMPbuf + 42), (ip_header*)(pkt_data + 14), 20);
    memcpy((u_char*)(ICMPbuf + 62), (u_char*)(pkt_data + 34), 8);

    //成功发送，打印和写入相关信息
    time(&rawtime);
    ptminfo = localtime(&rawtime);
    data_packet* data = (data_packet*)ICMPbuf;
    write_packet(fp, data, 1);
    printf("[%02d:%02d:%02d][发送]:IP数据包 sourceIP:", ptminfo->tm_hour, ptminfo->tm_min, ptminfo->tm_sec);
    print_ip(data->ipHeader.saddr.ip);
    printf("  targetIP:");
    print_ip(data->ipHeader.daddr.ip);
    printf("  sourceMAC:");
    print_mac(data->etherHeader.ether_shost);
    printf("  targetMAC:");
    print_mac(data->etherHeader.ether_dhost);
    printf("\n");
    //返回ICMP超时报告报文
    pcap_sendpacket(adhandle, (u_char*)ICMPbuf, 70);


}


DWORD WINAPI forwardThread(LPVOID lparam) {
    while (1) {
        //循环直至接收到数据包
        while (1) {
            if (pcap_next_ex(adhandle, &pkt_header, &pkt_data))
                break;
        }
        ether_header* eheader = (ether_header*)pkt_data;    
        if (memcmp(&(eheader->ether_dhost), &dev_mac, 6) == 0) {
            //包的以太帧目的MAC地址是本机  
            if (ntohs(eheader->ether_type) == 0x0800) {
                //包的以太帧类型表明是IP数据包
                data_packet* data = (data_packet*)pkt_data;
                //打印和写入相关信息
                time(&rawtime);
                ptminfo = localtime(&rawtime);
                printf("[%02d:%02d:%02d][接收]:IP数据包 sourceIP:", ptminfo->tm_hour, ptminfo->tm_min, ptminfo->tm_sec);
                print_ip(data->ipHeader.saddr.ip);
                printf("  targetIP:");
                print_ip(data->ipHeader.daddr.ip);
                printf("  sourceMAC:");
                print_mac(data->etherHeader.ether_shost);
                printf("  targetMAC:");
                print_mac(data->etherHeader.ether_dhost);
                printf("\n");
                write_packet(fp,data, 0);

                //如果接收到的IP数据包的TTL<=1，说明要返回超时报文
                if (data->ipHeader.ttl <= 1) {
                    ICMP_packet_send(11, 0);
                    continue;
                }

                //如果接收到的IP数据包的校验和错误，丢弃
                if (!checkChecksum(data)) {
                    cout << "校验和错误" << endl;
                    continue;
                }

                if (data->ipHeader.daddr.ip != dev_ip[0][1] && data->ipHeader.daddr.ip != dev_ip[0][0]) {
                    //包的目的IP不是本机接口中任意一个IP
                    if (not_broadcast(data)) {
                        //不是广播包
                        // 
                        //查找路由表中目的IP的下一跳地址，未找到则忽略
                        u_long tip = routerTable.router_table_search(data->ipHeader.daddr.ip);
                        if (tip == -1) {
                            cout << "目标ip未找到" << endl;
                            continue;
                        }

                        u_char* mac = new u_char[6];
                        if (tip == 0) {
                            //下一跳地址为0表明是直接投递
                            if (!arpTable.arp_table_search(data->ipHeader.daddr.ip, mac)) {
                                //在ARP缓存表中没有找到包目的IP对应项
                                arpTable.arp_table_add(data->ipHeader.daddr.ip);

                            }
                            arpTable.arp_table_search(data->ipHeader.daddr.ip, mac);
                        }
                        else {
                            //下一跳地址有意义
                            if (!arpTable.arp_table_search(tip, mac)) {
                                //在ARP缓存表中没有找到下一跳地址的对应项
                                arpTable.arp_table_add(tip);
                            }
                            arpTable.arp_table_search(tip, mac);
                        }
                        //修改包的以太帧的源MAC地址为本网卡设备MAC地址，目的MAC地址为查询ARP缓存表得到的物理地址
                        memcpy(data->etherHeader.ether_shost, data->etherHeader.ether_dhost, 6);
                        memcpy(data->etherHeader.ether_dhost, mac, 6);
                        //包的TTL减一
                        data->ipHeader.ttl -= 1;
                        //重新计算校验和
                        calChecksum(data);
                        int len = ntohs(data->ipHeader.tlen);
                        data_packet* curdata = (data_packet*)malloc(len + 14);
                        memcpy(curdata, data, len + 14);
                        if (pcap_sendpacket(adhandle, (u_char*)data, len+14) == 0){
                            //成功发送，打印和写入相关信息
                            time(&rawtime);
                            ptminfo = localtime(&rawtime);
                            write_packet(fp, curdata, 1);
                            printf("[%02d:%02d:%02d][发送]:IP数据包 sourceIP:", ptminfo->tm_hour, ptminfo->tm_min, ptminfo->tm_sec);
                            print_ip(curdata->ipHeader.saddr.ip);
                            printf("  targetIP:");
                            print_ip(curdata->ipHeader.daddr.ip);
                            printf("  sourceMAC:");
                            print_mac(curdata->etherHeader.ether_shost);
                            printf("  targetMAC:");
                            print_mac(curdata->etherHeader.ether_dhost);
                            printf("\n");
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
    int inum;
    int i = 0;
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
    if (i == 0)  return -1;
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

    int dev_ip_index = 0;
    for (pcap_addr* a = d->addresses; a; a = a->next) {
        if (a->addr->sa_family == AF_INET) {
            dev_ip[0][dev_ip_index] = (((struct sockaddr_in*)a->addr)->sin_addr.s_addr);
            dev_ip[1][dev_ip_index] = (((struct sockaddr_in*)a->netmask)->sin_addr.s_addr);

            dev_ip_index++;
        }
    }
    //获取网卡设备MAC地址
    pAddresses = nullptr;
    //IP_ADAPTER_DNS_SERVER_ADDRESS *pDnsServer=nullptr;
    ULONG outbuflen = 0;
    GetAdaptersAddresses(AF_UNSPEC, 0, NULL, pAddresses, &outbuflen);
    pAddresses = (IP_ADAPTER_ADDRESSES*)malloc(outbuflen);
    GetAdaptersAddresses(AF_INET, NULL, NULL, pAddresses, &outbuflen);
    //while (1)
    //{
    //    //简化成使用IP地址而不是设备GUID标识找到该设备
    //    if (strncmp((pAddresses->FirstUnicastAddress->Address.lpSockaddr->sa_data + 2), (d->addresses->addr->sa_data + 2), 4) == 0)
    //        break;
    //    pAddresses = pAddresses->Next;
    //}
    for (int i = 0; i < 6; i++)
        dev_mac[i] = pAddresses->PhysicalAddress[i];

    //初始化路由表，添加D项
    for (int i = 0; i < dev_ip_index; i++) {
        router_table_entry t;
        t.target_net = dev_ip[0][i] & dev_ip[1][i];
        t.mask = dev_ip[1][i];
        t.next_jump = 0;
        t.dev_ip_index = i;
        t.flag = FLAG_DIR;
        routerTable.router_table_add(t);
    }
    fp = fopen("log.txt", "a+");
    hThread = CreateThread(NULL, NULL, forwardThread, LPVOID(&routerTable), 0, &dwThreadId);
    int operation;
    while (1)
    {
        printf("输入后续操作\n1.打印路由表\n2.添加路由表项\n3.删除路由表项\n4.打印arp缓存\n");
        cin >> operation;
        if (operation == 1) {
            routerTable.print();
        }
        else if (operation == 2) {
            router_table_entry t;
            char userin_net[20];
            char userin_mask[20];
            char userin_nj[20];
            printf("输入目的网络：");
            cin >> userin_net;
            printf("输入掩码：");
            cin >> userin_mask;
            printf("输入下一跳：");
            cin >> userin_nj;
            t.mask = inet_addr(userin_mask);
            t.target_net = inet_addr(userin_net);
            t.next_jump = inet_addr(userin_nj);
            for (int i = 0; i < dev_ip_index; i++) {
                if ((dev_ip[0][i] & dev_ip[1][i]) == (t.mask & t.target_net)) {
                    t.dev_ip_index = i;
                    break;
                }
            }
            routerTable.router_table_add(t);
        }
        else if (operation == 3) {
            printf("输入要删除的表项编号：");
            int index;
            cin >> index;
            routerTable.router_table_delete(index);
        }
        else if (operation == 0) {
            break;
        }
        else if (operation == 4) {
            arpTable.print();
        }
        else {
            printf("无效操作码\n");
        }
    }
    pcap_close(adhandle);
    fclose(fp);
    system("pause");
    return 0;
}