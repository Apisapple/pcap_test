#include "pcap_test.h"

pcap_test::pcap_test()
{

}
pcap_test::~pcap_test(){
    pcap_close(handle);
}
// Try catch handler
int pcap_test::catch_Handle(char* dev, char errbuf[]){
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL)
    {
        fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
        return -1;
    }
    return 0;
}
int pcap_test::catch_res(){
    res = pcap_next_ex(handle, &header, &packet);
    set_l4type();
    set_l3type();
    set_offset();
    return res;
}
//setter
void pcap_test::set_l4type(){
    ip = (unsigned int)((packet[12] << 8) | packet[13]);
}
void pcap_test::set_l3type(){
    tcp = packet[23];
}
void pcap_test::set_offset(){
    offset = (packet[14] & 0x0f);
    tcp_len = packet[46] >> 4;
    D_port = ((packet[offset*4 + 16]<<8) | packet[offset*4 + 17]);
    S_port = ((packet[offset*4 + 14]<<8) | packet[offset*4 + 15]);
}

//getter
unsigned int pcap_test::get_ip(){
    return ip;
}
unsigned int pcap_test::get_size(){
    return header->caplen;
}
unsigned int pcap_test::get_tcp(){
    return tcp;
}

// Show information
void pcap_test::showMac(int Start){
    printf("%02X : %02X : %02X : %02X : %02X : %02X\n", packet[Start], packet[Start+1], packet[Start+2], packet[Start+3], packet[Start+4], packet[Start+5]);
}
void pcap_test::showIp(int Start){
    printf("%u.%u.%u.%u\n", packet[Start], packet[Start+1], packet[Start+2], packet[Start+3]);
}
void pcap_test::showPort(int Start){
    printf(" %u\n", ((packet[offset*4 + Start]<<8)| packet[offset*4 + Start+1]));
    //Destination_port = ((packet[offset*4 + 16]<<8) | packet[offset*4 + 17)
}
void pcap_test::showData(){

    // TCP length > 20
    if(tcp_len >5 ){
        printf("TCP data : ");
        for (int i = 0; i < tcp_len; i++) {
            printf("%02X " , packet[54 + i]);
        }
        printf("\n");
    }
    if(D_port == 80 || S_port == 80){
        printf("http info :");
        for(int i = 0; i < 10; i++){
            printf("%c ", packet[tcp_len * 4 + 34 + i]);
        }
        printf("\n");
    }
}
