#include "dot11.h"

void initialize_dot11(){
    radiotap_header = malloc(sizeof(RADIOTAP_HEADER));
    mgm_frame_struct = malloc(sizeof(MGM_FRAME_STRUCT));
}

int get(const unsigned char * packet)
{
    get_radiotap_header(packet); // get dot11 header length

    uint8_t * tmp_cdf_addr = (uint8_t *)(packet + radiotap_header->it_len);
    CDF tmp_cdf = {
        (uint8_t)(*tmp_cdf_addr & 3),          // version // 00000011
        (uint8_t)((*tmp_cdf_addr & 12) >> 2),  // type    // 00001100
        (uint8_t)(*tmp_cdf_addr >> 4),         // subtype
        *(tmp_cdf_addr + 1)                    // flags
    };

    if((tmp_cdf.type == MANAGEMENT_FRAME) && (tmp_cdf.subtype == BECONE_FRAME)){
        get_mgm_frame_struct(tmp_cdf, tmp_cdf_addr);
        return 1;
    }
    return 0;
}

void get_radiotap_header(const unsigned char * packet)
{
    radiotap_header = (RADIOTAP_HEADER *) packet;
}

void get_mgm_frame_struct(CDF cdf, uint8_t * start_addr)
{
    memcpy(&mgm_frame_struct->cdf, &cdf, sizeof(CDF));
    memcpy(&mgm_frame_struct->duration, start_addr+2, sizeof(MGM_FRAME_STRUCT)-sizeof(CDF));
}


void set(const unsigned char * packet)
{
    get(packet);
}

void reset()
{
    memset(radiotap_header, 0, sizeof(RADIOTAP_HEADER));
    memset(mgm_frame_struct, 0, sizeof(MGM_FRAME_STRUCT));
}

void print_BSSID(unsigned char * BSSID)
{
    printf("%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx\n",
            BSSID[0],
            BSSID[1],
            BSSID[2],
            BSSID[3],
            BSSID[4],
            BSSID[5]
            );
}

