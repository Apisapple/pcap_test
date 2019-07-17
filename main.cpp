//#include <pcap.h>
//#include <stdio.h>
#include "pcap_test.h"

void usage()
{
    printf("syntax: pcap_test <interface>\n");
    printf("sample: pcap_test wlan0\n");
}

int main(int argc, char *argv[])
{
    char *dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];

    // Wron argc
    if (argc != 2)
    {
        usage();
        return -1;
    }
    /*-----------------------------------*/
    pcap_test* tester = new pcap_test();
    tester->catch_Handle(dev,errbuf);

    while (true)
    {
        if (tester->catch_res() == 0)
            continue;
        else if (tester->catch_res() == -1 || tester->catch_res() == -2)
            break;

        // IPv4 확인
        if (0x0800 == tester->get_ip())
        {
            printf("=============================\n");
            //          Show packet Size
            printf("%u bytes captured\n",  tester->get_size());

            //          Show mac Address
            printf("S_mac/");
            tester->showMac(0);
            printf("D_mac/");
            tester->showMac(6);

            // TCP 확인
            if (0x06 == tester->get_tcp())
            {
                //              Show IP
                printf("S_ip :");
                tester->showIp(26);
                printf("D_ip :");
                tester->showIp(30);

                //              Show Port number
                printf("S_port :");
                tester->showPort(14);
                printf("D_port :");
                tester->showPort(16);

                tester->showData();
                printf("\n");
            }
        }
        printf("=============================\n");
    }
    return 0;
}
