#ifndef DOT11_H
#define DOT11_H
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

typedef enum frame_control_field_type {
    MANAGEMENT_FRAME, // 00
    CONTROL_FRAME,    // 01
    DATA_FRAME        // 11
} FCF_TYPE;

typedef enum fcf_management_frame_subtype {
    AID_REQUEST_FRAME       = 0,
    AID_RESPONSE_FRAME      = 1,
    AID_RE_REQUEST_FRAME    = 2,
    AID_RE_RESPONSE_FRAME   = 3,
    PROBE_REQUEST_FRAME     = 4,
    PROBE_RESPONSE_FRAME    = 5,
    BECONE_FRAME            = 8, // [A]
    ATIM_FRAME              = 9,
    DISASSOCIATION_FRAME    = 10,
    AUTHENTICATION_FRAME    = 11,
    DEAUTHENTICATION_FRAME  = 12
} FCF_MGM_SUBTYPE;

typedef struct ieee80211_radiotap_header {
    uint8_t  it_version;     /* set to 0 */
    uint8_t  it_pad;
    unsigned short it_len;   /* entire length */
    uint32_t it_present;     /* fields present */ // 여러개 있다..
} RADIOTAP_HEADER;

typedef struct common_dot11_field{ // 2byte
    uint8_t version; // static : 0, 2bit
    uint8_t type;    // frame type, 2bit
    uint8_t subtype; // sub type  , 4bit
    uint8_t flag;    // FCF_FLAG  , 8bit
} CDF;

typedef struct management_frame{
    CDF      cdf;          // frame_control_field
    uint16_t duration;
    uint8_t  dest_addr[6];
    uint8_t  src_addr[6];
    uint8_t  BSSID[6];
    uint16_t  number;       // sequence number(12bit) + fragment number(4bit)
} MGM_FRAME_STRUCT;

typedef struct ap_information{
    uint8_t            BSSID[6];
} AP;

RADIOTAP_HEADER  * radiotap_header; // = malloc(sizeof(RADIOTAP_HEADER));
MGM_FRAME_STRUCT * mgm_frame_struct; //= malloc(sizeof(MGM_FRAME_STRUCT));

//const unsigned char * packet;

int get(const unsigned char * packet);
void get_radiotap_header(const unsigned char * packet);
void get_mgm_frame_struct(CDF cdf, uint8_t * start_addr);
void print_BSSID(unsigned char * BSSID);

void set(const unsigned char * packet);
void save_info(int flag);
void reset();
void print();

#endif // DOT11_H
