#pragma once

#include <pcap.h>
#include <stdio.h>

class pcap_test
{
private:
    struct pcap_pkthdr *header;
    pcap_t *handle;

    unsigned int tcp;
    unsigned int ip;

    const u_char *packet;
    int res;
    //IP offset
    int offset;
    //TCP offset
    int t_offset;
    int tcp_len;
    int D_port;
    int S_port;
public:
    pcap_test();
    ~pcap_test();
    int catch_Handle(char* dev, char errbuf[]);
    int catch_res();

    //setter
    void set_l4type();
    void set_l3type();
    void set_offset();

    //getter
    unsigned int get_size();
    unsigned int get_ip();
    unsigned int get_tcp();

    //show information
    void showIp(int Start);
    void showMac(int Start);
    void showPort(int Start);
    void showData();
};

