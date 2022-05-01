#include <stdio.h>
#include <stdlib.h>


struct IP {
    u_int8_t ip_ihl;
    u_int8_t ip_tos;
    u_int16_t ip_total_len;
    u_int16_t ip_id;
    u_int16_t ip_frag_offset;
    u_int8_t ip_ttl;
    u_int8_t ip_proto;
    u_int16_t ip_checksum;
    u_int32_t ip_src_addr;
    u_int32_t ip_dst_addr;
};

struct ICMP {
    
};