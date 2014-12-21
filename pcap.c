/**
 * @file
 * pcap file format support
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/**
 * pcap file header format
 */
struct pcap_file_header {
    u_int32_t magic;
#define PCAP_FILE_HEADER_MAGIC 0xA1B2C3D4
    u_int16_t version_major;
    u_int16_t version_minor;
#define PCAP_FILE_HEADER_VERSION_MAJOR 2
#define PCAP_FILE_HEADER_VERSION_MINOR 4
    int32_t thiszone;
    u_int32_t sigfigs;
    u_int32_t snaplen;
#define PCAP_FILE_HEADER_SNAPLEN 0xFFFF
    u_int32_t linktype;
#define PCAP_FILE_HEADER_LINKTYPE_ETHERNET 1
};

/**
 * pcap packet header format
 */
struct pcap_packet_header {
    struct {
        u_int32_t tv_sec;
        u_int32_t tv_usec;
    } ts;
    u_int32_t caplen;
    u_int32_t len;
};

int pcap_file_is_pcap(FILE *fp)
{
    u_int32_t magic;
    int len;

    len = fread(&magic, 1, 4, fp);
    if (len == 4 && magic == htobe32(PCAP_FILE_HEADER_MAGIC)) {
        return 1;
    }
    return 0;
}
