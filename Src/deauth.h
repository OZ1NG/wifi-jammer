#ifndef DEAUTH_H
#define DEAUTH_H
#include <stdint.h>
#include <pcap.h>

struct Ieee80211_radiotap_header {
    uint8_t  it_version;     /* set to 0 */
    uint8_t  it_pad;
    unsigned short it_len;   /* entire length */
    uint32_t it_present;     /* fields present */ // 여러개 있다..
    uint32_t dummy;          // rate... etc....
};

struct Deauth_packet{
    struct Ieee80211_radiotap_header radiotap;
    //struct Common_dot11_header common_dot11;
    uint16_t common_dot11;
    uint16_t duration;
    uint8_t  dest_addr[6];
    uint8_t  src_addr[6];
    uint8_t  BSSID[6];
    uint16_t  number;       // sequence number(12bit) + fragment number(4bit)
    uint16_t fixed_param;
};

//struct Common_dot11_header common_dot11_h = {0, 0, 12, 0};

void initialize(struct Deauth_packet * dp);

//struct Deauth_packet deauth_packet;
void send_packet(pcap_t * pcap, const u_char * packet_data);

#endif // DEAUTH_H
