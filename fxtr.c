#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <pcap.h>
#include <getopt.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <netinet/tcp.h>

#include "jsmn.h"
#include "fxtr.h"
#include "es.h"

#define BULK_BUF_SIZE (1024 * 256)
#define STR_SIZE 1024
#define LONG_STR_SIZE (STR_SIZE * 5)
#define MAX_FILES 5
#define QUOTE(...) #__VA_ARGS__

#define TYPE_NONE       0
#define TYPE_SESSIONID  1
#define TYPE_ATTACHID   2
struct pcap_sf_pkthdr {
        bpf_int32 tv_sec;           /* seconds */
        bpf_int32 tv_usec;          /* microseconds */
        bpf_u_int32 caplen;         /* length of portion present */
        bpf_u_int32 len;            /* length this packet (off wire) */
};

struct nread_ip {
    u_int8_t        ip_vhl;          /* header length, version    */
#define IP_V(ip)    (((ip)->ip_vhl & 0xf0) >> 4)
#define IP_HL(ip)   ((ip)->ip_vhl & 0x0f)
    u_int8_t        ip_tos;          /* type of service           */
    u_int16_t       ip_len;          /* total length              */
    u_int16_t       ip_id;           /* identification            */
    u_int16_t       ip_off;          /* fragment offset field     */
#define IP_DF 0x4000                 /* dont fragment flag        */
#define IP_MF 0x2000                 /* more fragments flag       */
#define IP_OFFMASK 0x1fff            /* mask for fragmenting bits */
    u_int8_t        ip_ttl;          /* time to live              */
    u_int8_t        ip_p;            /* protocol                  */
    u_int16_t       ip_sum;          /* checksum                  */
    struct  in_addr ip_src, ip_dst;  /* source and dest address   */
};

struct nread_tcp {
    u_short th_sport; /* source port            */
    u_short th_dport; /* destination port       */
    tcp_seq th_seq;   /* sequence number        */
    tcp_seq th_ack;   /* acknowledgement number */
#if BYTE_ORDER == LITTLE_ENDIAN
    u_int th_x2:4,    /* (unused)    */
    th_off:4;         /* data offset */
#endif
#if BYTE_ORDER == BIG_ENDIAN
    u_int th_off:4,   /* data offset */
    th_x2:4;          /* (unused)    */
#endif
    u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
    u_short th_win; /* window */
    u_short th_sum; /* checksum */
    u_short th_urp; /* urgent pointer */
};

/**
  * callback function parse session json to extract all payload from this session
  * @input[in] text json string
  */
static void _parse_session(char *text);
/**
  * callback function when parse files_v3 json string to extract filepath
  * @input[in] text json string
  * @input[out]path filepath 
  */
static void _parse_file(char *text, char *path);
/**
  * Read filepath from filenum
  */
static void _es_read_filepath(int filenum, char *path);

static void _read_attach_id_from_session(char *text, char *attach_id);
static void _extract_file(char *text);

static void _get_uniq_name(const char *inname, char *outname);

/**
  * Extract network payload from the session with filter cond : ip, port, first packet timestamp, lastpacket timestamp)
  */
static void _es_extract_file(uint32_t ip, uint32_t port, long long unsigned int fpd, long long unsigned int lpd);
/**
  * Read payload from pcap file
  * @param[in] fp Filepointer to pcap file
  * @param[in] pos Offset of the packet
  * @param[out] buff Payload
  * @return Payload length
  */
static uint32_t _read_packet(FILE *fp, uint32_t pos, char *buff);
/**
  * Compare the content of a jsmntok with a string
  * @return 0 if equal
  */
static int _jsoneq(const char *json, jsmntok_t *tok, const char *s);

static char paths[LONG_STR_SIZE];
static char filedir[STR_SIZE] = "/home/meo/opensource/fxtr/outfiles";
static char *ES_SESSION_TBL = "/sessions-*/_search?pretty";
static char *ES_ATTACH_TBL = "/attach-*/_search?pretty";
static char *ES_FILE_TBL = "/files_v3/_search?pretty";

char *fxtr_by_sessionid(const char *id)
{
    char query[STR_SIZE];
    char attach_id[STR_SIZE];

    sprintf(query, "{\"query\": {\"terms\": {\"_id\": [\"%s\"] }}}", id);
    char *json = es_query(ES_SESSION_TBL, query);
    _read_attach_id_from_session(json, attach_id);
    return fxtr_by_attachid(attach_id);
}

char *fxtr_by_attachid(const char *id)
{
    char query[STR_SIZE];

    sprintf(query, "{\"query\": {\"terms\": {\"_id\": [\"%s\"] }}}", id);

    strcpy(paths, "");
    char *json = es_query(ES_ATTACH_TBL, query);
    _extract_file(json);
    if (strlen(paths) > 0) {
        return paths;
    }
    else
        return NULL;
}

static void _read_attach_id_from_session(char *text, char *attach_id)
{
    int r;
    jsmn_parser parser;
    jsmntok_t t[STR_SIZE];

    jsmn_init(&parser);
    r = jsmn_parse(&parser, text, strlen(text), t, sizeof(t)/sizeof(t[0]));
    if (r < 0) {
        printf("Failed to parse JSON: %d\n", 4);
    }
    int i;
    for (i = 0; i < r; i++) {
        if (_jsoneq(text, &t[i], "eattach") == 0) {
            i = i + 2;
            snprintf(attach_id, t[i].end - t[i].start + 1,"%s", text + t[i].start);
            break;
        }
    }
}

static void _extract_file(char *text)
{
    int r;
    jsmn_parser parser;
    jsmntok_t t[STR_SIZE];
    char buf[STR_SIZE];
    uint32_t dataip;
    uint32_t dataport;
    uint64_t fpd;
    uint64_t lpd;

    jsmn_init(&parser);
    r = jsmn_parse(&parser, text, strlen(text), t, sizeof(t)/sizeof(t[0]));
    if (r < 0) {
        printf("Failed to parse JSON: %d\n", 4);
    }
    int i;
    for (i = 0; i < r; i++) {
        if (_jsoneq(text, &t[i], "dataip") == 0) {
            snprintf(buf, t[i+1].end - t[i+1].start + 1,"%s", text + t[i+1].start);
            dataip = atoi(buf);
        }
        else if (_jsoneq(text, &t[i], "dataport") == 0) {
            snprintf(buf, t[i+1].end - t[i+1].start + 1,"%s", text + t[i+1].start);
            dataport = atoi(buf);
        }
        else if (_jsoneq(text, &t[i], "fpd") == 0) {
            snprintf(buf, t[i+1].end - t[i+1].start + 1,"%s", text + t[i+1].start);
            fpd = atol(buf);
        }
        else if (_jsoneq(text, &t[i], "lpd") == 0) {
            snprintf(buf, t[i+1].end - t[i+1].start + 1,"%s", text + t[i+1].start);
            lpd = atol(buf);
        }
    }
    _es_extract_file(dataip, dataport, fpd, lpd);
}

static void _es_extract_file(uint32_t ip, uint32_t port, long long unsigned int fpd, long long unsigned int lpd)
{
    char query[STR_SIZE];
    if (ip != 0) {
        sprintf(query, "{\"query\" : {"
                            "\"bool\" : {"
                                "\"should\" : ["
                                    "{ \"bool\" : {"
                                        "\"must\" : ["
                                            "{ \"match\": {\"p2\" : %u }},"
                                            "{ \"match\": {\"a2\" : %u }},"
                                            "{ \"range\": {\"fpd\" : { \"gte\" : %llu, \"lte\" : %llu }}}"
                                        "]"
                                     "}},"
                                    "{ \"bool\" : {"
                                        "\"must\" : ["
                                            "{ \"match\": {\"p1\" : %u }},"
                                            "{ \"match\": {\"a1\" : %u }},"
                                            "{ \"range\": {\"fpd\" : { \"gte\" : %llu, \"lte\" : %llu }}}"
                                        "]"
                                     "}}"
                               "]"
                          "}"
                "}}"
                , port, ip
                , fpd, lpd
                , port, ip
                , fpd, lpd);
    } else {
        sprintf(query, "{\"query\" : {"
                            "\"bool\" : {"
                                "\"should\" : ["
                                    "{ \"bool\" : {"
                                        "\"must\" : ["
                                            "{ \"match\": {\"p2\" : %u }},"
                                            "{ \"range\": {\"fpd\" : { \"gte\" : %llu, \"lte\" : %llu }}}"
                                        "]"
                                     "}},"
                                    "{ \"bool\" : {"
                                        "\"must\" : ["
                                            "{ \"match\": {\"p1\" : %u }},"
                                            "{ \"range\": {\"fpd\" : { \"gte\" : %llu, \"lte\" : %llu }}}"
                                        "]"
                                     "}}"
                               "]"
                          "}"
                "}}"
                , port
                , fpd, lpd
                , port
                , fpd, lpd);
    }
    char *json = es_query(ES_SESSION_TBL, query);
    _parse_session(json);
}

static void _parse_session(char *text)
{
    int r;
    jsmn_parser parser;
    jsmntok_t t[256];

    char ps[1024];
    ps[0] = '\0';

    jsmn_init(&parser);
    r = jsmn_parse(&parser, text, strlen(text), t, sizeof(t)/sizeof(t[0]));
    if (r < 0) {
        printf("Failed to parse JSON: %d\n", r);
    }
    int i;
    int found_id = 0;
    for (i = 1; i < r; i++) {
        if (_jsoneq(text, &t[i], "ps") == 0) {
            if (found_id) {
                printf("ERROR: more than two sessions exist\n");
                break;
            }
            found_id = 1;
            snprintf(ps, t[i+1].end - t[i+1].start + 1, "%s", text + t[i+1].start);
        }
    }
    //Parse file position
    if (!found_id) {
        printf("No session found\n");
        return;
    }
    char c;
    char *p = ps;
    int pos;
    uint32_t pktlen;
    uint32_t total = 0;
    char buff[BULK_BUF_SIZE];
    char path[STR_SIZE];
    FILE *fp = NULL;
    FILE *wfp = NULL;
    while (1) {
        while ((c = *p) != '\0' && !isdigit(c) && c != '-') {
            p++;
        }
        sscanf(p, "%d", &pos);
        if (pos < 0) {
            _es_read_filepath(-pos, path);
            if (fp != NULL) fclose(fp);
            fp = fopen(path, "r");
            if (fp == NULL) {
                printf("Cannot open file %s\n", path);
                break;
            }
        }
        else {
            pktlen = _read_packet(fp, pos, buff);
            if (pktlen > 0) {
                if (wfp == NULL) {
                    char outpath[STR_SIZE];
                    char uniq_name[STR_SIZE];
                    sprintf(outpath, "%s/ftp_%ld.out", filedir, time(NULL));
                    _get_uniq_name(outpath, uniq_name);
                    wfp = fopen(uniq_name, "w");
                    if (!wfp) {
                        printf("Cannot open file for writting %s\n", uniq_name);
                        exit(1);
                    }
                    if (strlen(paths) > 0) {
                        strcat(paths, ";");
                    }
                    strcat(paths, uniq_name);
                }
                fwrite(buff, 1, pktlen, wfp);
                total += pktlen;
            }
        }
        p = strchr(p, ',');
        if (p == NULL) {
            break;
        }
    }
    if (fp) {
        fclose(fp);
    }
    if (wfp) {
        fclose(wfp);
    }
    printf("Filesize extracted %u\n", total);
}

static void _es_read_filepath(int filenum, char *path)
{
    char query[STR_SIZE];
    sprintf(query, "{ \"query\": {\"match\": {\"num\": %d}}}", filenum);
    char *json = es_query(ES_FILE_TBL, query);
    _parse_file(json, path);
}

/*
 * Callback function parse output generate by query to read data from index files_v3 and extract filepath
 */
static void _parse_file(char *text, char *path)
{
    int r;
    jsmn_parser parser;
    jsmntok_t t[128];

    jsmn_init(&parser);
    r = jsmn_parse(&parser, text, strlen(text), t, sizeof(t)/sizeof(t[0]));
    if (r < 0) {
        printf("Failed to parse JSON: %d\n", r);
    }
    int i;
    int found_id = 0;
    for (i = 1; i < r; i++) {
        if (_jsoneq(text, &t[i], "name") == 0) {
            snprintf(path, t[i+1].end - t[i+1].start + 1, "%s", text + t[i+1].start);
        }
    }
}

static uint32_t _read_packet(FILE *fp, uint32_t pos, char *buff)
{
    fseek(fp, pos, SEEK_SET);
    const int BUF_SIZE = 2048;
    struct pcap_sf_pkthdr pkthdr;
    char *pktdata;
    uint32_t payload_len = 0;

    fread(&pkthdr, sizeof(pkthdr), 1, fp);
    if (pkthdr.caplen > 0) {
        pktdata = (char *)malloc(BULK_BUF_SIZE);
        fread(pktdata, pkthdr.caplen, 1, fp);
        struct ether_header *eptr = (struct ether_header *)pktdata;
        u_short ether_type = ntohs(eptr->ether_type);
        if (ether_type == ETHERTYPE_IP) {
            const struct nread_ip *ip = (struct nread_ip*)(pktdata + sizeof(struct ether_header));
            if (ip->ip_p == 6) {  //TCP protocol
                const struct nread_tcp *tcp = (struct nread_tcp *)(pktdata + sizeof(struct ether_header) + sizeof(struct nread_ip));
               payload_len = ntohs(ip->ip_len) - (IP_HL(ip) + tcp->th_off) * 4;
               if (payload_len > 0) {
                   memcpy(buff, (char *)tcp + tcp->th_off * 4, payload_len);
               }

            }
        }
        free(pktdata);
    }
    return payload_len;
}

static int _jsoneq(const char *json, jsmntok_t *tok, const char *s) {
    if (tok->type == JSMN_STRING
            && (int) strlen(s) == tok->end - tok->start
            && strncmp(json + tok->start, s, tok->end - tok->start) == 0) {
            return 0;
    }
    return -1;
}

static void _get_uniq_name(const char *inname, char *outname)
{
    static unsigned int idx = 0;
    strcpy(outname, inname);
    while (!access(outname, F_OK)) {
        idx++;
        sprintf(outname, "%s_%u", inname, idx);
    }
}

int main(int argc, char **argvs)
{
    char id[STR_SIZE];
    int type = TYPE_NONE;;
    static struct option long_options[] = {
        {"sessionid", required_argument, 0, 's'},
        {"attachid", required_argument, 0, 'a'},
        {"dir", required_argument, 0, 'd'},
        {0,0,0,0}
    };
    int option_index = 0;
    int c;
    while ((c = getopt_long(argc, argvs, "s:a:d:", long_options, &option_index)) != -1) {
        switch (c) {
            case 's':
                strcpy(id, optarg);
                type = TYPE_SESSIONID;
                break;
            case 'a':
                strcpy(id, optarg);
                type = TYPE_ATTACHID;
                break;
            case 'd':
                strcpy(filedir, optarg);
                break;
        }
    }
    if (type == TYPE_NONE) {
        printf("Usage: \n");
        printf("\tfxtr [-s <sessionid>] [-a <attachid>]\n");
        exit(0);
    }
    char *result;
    es_init();
    if (type == TYPE_SESSIONID) {
        result = fxtr_by_sessionid(id);
    }
    else {
        result = fxtr_by_attachid(id);
    }
    if (result != NULL) {
        printf("%s\n", result);
    }
    es_close();

    return 0;
}

