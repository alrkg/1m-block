#pragma once
#include <stdint.h>

#pragma pack(push, 1)
struct ipv4Hdr
{
    uint8_t verIhl;
    uint8_t dscpEcn;
    uint16_t totalLen;
    uint16_t id;
    uint16_t flagsOffset;
    uint8_t ttl;
    uint8_t proto;
    uint16_t checksum;
    uint32_t srcIp;
    uint32_t dstIp;
};

struct tcpHdr {
    uint16_t srcPort;
    uint16_t dstPort;
    uint32_t seqNum;
    uint32_t ackNum;
    uint16_t offsetFlags;
    uint16_t windowSize;
    uint16_t checksum;
    uint16_t urgPointer;
};
#pragma pack(pop)
