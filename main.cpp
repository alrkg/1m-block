#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <string.h>
#include <unordered_set>
#include <fstream>
#include "headers.h"
#include <chrono>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>

#include <libnetfilter_queue/libnetfilter_queue.h>

void parse(int argc) {
    if (argc != 2) {
        fprintf(stderr, "syntax : 1m-block <site list file>\n");
        fprintf(stderr, "sample : 1m-block top-1m.txt\n");
        exit(1);
    }
}


std::unordered_set<std::string> loadDomains(const std::string& filename, size_t expectedSize = 800000) {
    std::ifstream infile(filename);
    std::string line;
    std::unordered_set<std::string> domainSet;
    domainSet.reserve(expectedSize);

    if (!infile) {
        fprintf(stderr, "Error: Failed to open file %s\n", filename.c_str());
        exit(1);
    }

    while (std::getline(infile, line)) {
        size_t commaPos = line.find(',');
        if (commaPos != std::string::npos) {
            std::string domain = line.substr(commaPos + 1);
            domainSet.insert(domain);
        }
    }
    return domainSet;
}


void setupNFQueue() {
    system("sudo iptables -F");
    system("sudo iptables -A INPUT -j NFQUEUE --queue-num 0");
    system("sudo iptables -A OUTPUT -j NFQUEUE --queue-num 0");
}


static u_int32_t returnId(struct nfq_data *tb)
{
    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(tb);
    return ph ? ntohl(ph->packet_id) : 0;
}


static std::string extractHttpHost(struct nfq_data *tb){
    unsigned char *data;
    int ret = nfq_get_payload(tb, &data);

    if (ret >= 0){
        ipv4Hdr* ipv4 = (ipv4Hdr*)data;
        if (ipv4->proto != 0x06) return "";
        int ipHdrLen = (ipv4->verIhl & 0x0F) * 4;

        tcpHdr* tcp = (tcpHdr*)((unsigned char*)ipv4 + ipHdrLen);
        if (ntohs(tcp->dstPort) != 80) return "";
        int tcpHdrLen = ((tcp->offsetFlags >> 4) & 0x0F) * 4;

        unsigned char* http = (unsigned char*)tcp + tcpHdrLen;

        while (*http == ' ' || *http == '\t' || *http == '\r' || *http == '\n') http++;
        if (strncmp((char*)http, "GET ", 4) == 0 || strncmp((char*)http, "POST ", 5) == 0){
            char* hostStart = strstr((char*)http, "Host: ");

            if (hostStart) {
                hostStart += strlen("Host: ");
                char* hostEnd = strstr(hostStart, "\r\n");

                if (hostEnd) return std::string(hostStart, hostEnd);
            }
        }
    }
    return "";
}


static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
              struct nfq_data *nfa, void *data)
{
    u_int32_t id = returnId(nfa);

    std::unordered_set<std::string>* domainSet = static_cast<std::unordered_set<std::string>*>(data);
    std::string host = extractHttpHost(nfa);

    auto start = std::chrono::high_resolution_clock::now();
    bool isBlocked = !host.empty() && domainSet->find(host) != domainSet->end();
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> searchDuration = end - start;

    if (isBlocked) {
        printf("Blocked domain: %s (found in %.8f seconds)\n", host.c_str(), searchDuration.count());
        return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
    }

    if (!host.empty()) printf("%s not blocked (search took %.8f seconds)\n", host.c_str(), searchDuration.count());

    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}


int main(int argc, char* argv[])
{
    parse(argc);
    setupNFQueue();

    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    int fd;
    int rv;
    char buf[4096] __attribute__ ((aligned));

    printf("opening library handle\n");
    h = nfq_open();
    if (!h) {
        fprintf(stderr, "error during nfq_open()\n");
        exit(1);
    }

    printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_unbind_pf()\n");
        exit(1);
    }

    printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_bind_pf()\n");
        exit(1);
    }

    auto start = std::chrono::high_resolution_clock::now();
    std::unordered_set<std::string> domainSet = loadDomains(argv[1]);
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> loadDuration = end - start;
    printf("Loded %zu domains in %.8f seconds\n", domainSet.size(), loadDuration.count());

    printf("binding this socket to queue '0'\n");
    qh = nfq_create_queue(h, 0, &cb, &domainSet);
    if (!qh) {
        fprintf(stderr, "error during nfq_create_queue()\n");
        exit(1);
    }

    printf("setting copy_packet mode\n");
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "can't set packet_copy mode\n");
        exit(1);
    }
    fputc('\n', stdout);

    fd = nfq_fd(h);

    for (;;) {
        if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
            nfq_handle_packet(h, buf, rv);
            continue;
        }

        if (rv < 0 && errno == ENOBUFS) continue;

        perror("recv failed");
        break;
    }

    printf("unbinding from queue 0\n");
    nfq_destroy_queue(qh);

    printf("closing library handle\n");
    nfq_close(h);

    exit(0);
}
