/**
 * Packet Utils - Implementação
 * Utilitários para manipulação de pacotes de rede
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "packet_utils.h"

// Variáveis globais
static int g_initialized = 0;

// Funções de inicialização
int packet_utils_init(void) {
    if (g_initialized) {
        return 0;
    }
    
    printf("[*] Inicializando Packet Utils\n");
    
    // Inicializar seed para rand()
    srand(time(NULL));
    
    g_initialized = 1;
    printf("[+] Packet Utils inicializado\n");
    
    return 0;
}

void packet_utils_cleanup(void) {
    if (!g_initialized) {
        return;
    }
    
    printf("[*] Limpando Packet Utils\n");
    g_initialized = 0;
}

// Funções de checksum
unsigned short calculate_ip_checksum(struct iphdr *ip_hdr) {
    unsigned short *ptr = (unsigned short *)ip_hdr;
    int len = ip_hdr->ihl * 4;
    unsigned int sum = 0;
    
    // Soma todos os words
    for (int i = 0; i < len / 2; i++) {
        sum += ntohs(ptr[i]);
    }
    
    // Adiciona carry se necessário
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    // Complemento de 1
    return htons(~sum);
}

unsigned short calculate_tcp_checksum(struct iphdr *ip_hdr, struct tcphdr *tcp_hdr) {
    struct {
        unsigned long saddr;
        unsigned long daddr;
        unsigned char zero;
        unsigned char protocol;
        unsigned short tcp_len;
    } pseudo_header;
    
    pseudo_header.saddr = ip_hdr->saddr;
    pseudo_header.daddr = ip_hdr->daddr;
    pseudo_header.zero = 0;
    pseudo_header.protocol = IPPROTO_TCP;
    pseudo_header.tcp_len = htons(ntohs(ip_hdr->tot_len) - (ip_hdr->ihl * 4));
    
    // Calcular checksum do pseudo-header + TCP header + dados
    unsigned short *ptr = (unsigned short *)&pseudo_header;
    int len = sizeof(pseudo_header) + ntohs(pseudo_header.tcp_len);
    unsigned int sum = 0;
    
    // Soma pseudo-header
    for (int i = 0; i < sizeof(pseudo_header) / 2; i++) {
        sum += ntohs(ptr[i]);
    }
    
    // Soma TCP header e dados
    ptr = (unsigned short *)tcp_hdr;
    int tcp_len = ntohs(pseudo_header.tcp_len);
    
    for (int i = 0; i < tcp_len / 2; i++) {
        sum += ntohs(ptr[i]);
    }
    
    // Adiciona carry se necessário
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    // Complemento de 1
    return htons(~sum);
}

unsigned short calculate_udp_checksum(struct iphdr *ip_hdr, struct udphdr *udp_hdr) {
    struct {
        unsigned long saddr;
        unsigned long daddr;
        unsigned char zero;
        unsigned char protocol;
        unsigned short udp_len;
    } pseudo_header;
    
    pseudo_header.saddr = ip_hdr->saddr;
    pseudo_header.daddr = ip_hdr->daddr;
    pseudo_header.zero = 0;
    pseudo_header.protocol = IPPROTO_UDP;
    pseudo_header.udp_len = udp_hdr->len;
    
    // Calcular checksum do pseudo-header + UDP header + dados
    unsigned short *ptr = (unsigned short *)&pseudo_header;
    int len = sizeof(pseudo_header) + ntohs(udp_hdr->len);
    unsigned int sum = 0;
    
    // Soma pseudo-header
    for (int i = 0; i < sizeof(pseudo_header) / 2; i++) {
        sum += ntohs(ptr[i]);
    }
    
    // Soma UDP header e dados
    ptr = (unsigned short *)udp_hdr;
    int udp_len = ntohs(udp_hdr->len);
    
    for (int i = 0; i < udp_len / 2; i++) {
        sum += ntohs(ptr[i]);
    }
    
    // Adiciona carry se necessário
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    // Complemento de 1
    return htons(~sum);
}

unsigned short calculate_icmp_checksum(struct icmphdr *icmp_hdr, int len) {
    unsigned short *ptr = (unsigned short *)icmp_hdr;
    unsigned int sum = 0;
    
    // Soma todos os words
    for (int i = 0; i < len / 2; i++) {
        sum += ntohs(ptr[i]);
    }
    
    // Adiciona carry se necessário
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    // Complemento de 1
    return htons(~sum);
}

// Funções de manipulação de pacotes
int create_syn_packet(char *packet, const char *src_ip, const char *dst_ip, 
                     int src_port, int dst_port) {
    struct iphdr *ip_hdr = (struct iphdr *)packet;
    struct tcphdr *tcp_hdr = (struct tcphdr *)(packet + sizeof(struct iphdr));
    
    // Configurar cabeçalho IP
    ip_hdr->ihl = 5;
    ip_hdr->version = 4;
    ip_hdr->tos = 0;
    ip_hdr->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
    ip_hdr->id = htons(rand());
    ip_hdr->frag_off = 0;
    ip_hdr->ttl = 64;
    ip_hdr->protocol = IPPROTO_TCP;
    ip_hdr->check = 0;
    ip_hdr->saddr = inet_addr(src_ip);
    ip_hdr->daddr = inet_addr(dst_ip);
    
    // Configurar cabeçalho TCP
    tcp_hdr->source = htons(src_port);
    tcp_hdr->dest = htons(dst_port);
    tcp_hdr->seq = rand();
    tcp_hdr->ack_seq = 0;
    tcp_hdr->doff = 5;
    tcp_hdr->fin = 0;
    tcp_hdr->syn = 1;
    tcp_hdr->rst = 0;
    tcp_hdr->psh = 0;
    tcp_hdr->ack = 0;
    tcp_hdr->urg = 0;
    tcp_hdr->window = htons(65535);
    tcp_hdr->check = 0;
    tcp_hdr->urg_ptr = 0;
    
    // Calcular checksums
    tcp_hdr->check = calculate_tcp_checksum(ip_hdr, tcp_hdr);
    ip_hdr->check = calculate_ip_checksum(ip_hdr);
    
    return sizeof(struct iphdr) + sizeof(struct tcphdr);
}

int create_udp_packet(char *packet, const char *src_ip, const char *dst_ip,
                     int src_port, int dst_port, const char *payload, int payload_len) {
    struct iphdr *ip_hdr = (struct iphdr *)packet;
    struct udphdr *udp_hdr = (struct udphdr *)(packet + sizeof(struct iphdr));
    char *data = (char *)(packet + sizeof(struct iphdr) + sizeof(struct udphdr));
    
    // Configurar cabeçalho IP
    ip_hdr->ihl = 5;
    ip_hdr->version = 4;
    ip_hdr->tos = 0;
    ip_hdr->tot_len = sizeof(struct iphdr) + sizeof(struct udphdr) + payload_len;
    ip_hdr->id = htons(rand());
    ip_hdr->frag_off = 0;
    ip_hdr->ttl = 64;
    ip_hdr->protocol = IPPROTO_UDP;
    ip_hdr->check = 0;
    ip_hdr->saddr = inet_addr(src_ip);
    ip_hdr->daddr = inet_addr(dst_ip);
    
    // Configurar cabeçalho UDP
    udp_hdr->source = htons(src_port);
    udp_hdr->dest = htons(dst_port);
    udp_hdr->len = htons(sizeof(struct udphdr) + payload_len);
    udp_hdr->check = 0;
    
    // Copiar payload
    if (payload && payload_len > 0) {
        memcpy(data, payload, payload_len);
    }
    
    // Calcular checksums
    udp_hdr->check = calculate_udp_checksum(ip_hdr, udp_hdr);
    ip_hdr->check = calculate_ip_checksum(ip_hdr);
    
    return sizeof(struct iphdr) + sizeof(struct udphdr) + payload_len;
}

int create_icmp_packet(char *packet, const char *src_ip, const char *dst_ip,
                      int type, int code, const char *payload, int payload_len) {
    struct iphdr *ip_hdr = (struct iphdr *)packet;
    struct icmphdr *icmp_hdr = (struct icmphdr *)(packet + sizeof(struct iphdr));
    char *data = (char *)(packet + sizeof(struct iphdr) + sizeof(struct icmphdr));
    
    // Configurar cabeçalho IP
    ip_hdr->ihl = 5;
    ip_hdr->version = 4;
    ip_hdr->tos = 0;
    ip_hdr->tot_len = sizeof(struct iphdr) + sizeof(struct icmphdr) + payload_len;
    ip_hdr->id = htons(rand());
    ip_hdr->frag_off = 0;
    ip_hdr->ttl = 64;
    ip_hdr->protocol = IPPROTO_ICMP;
    ip_hdr->check = 0;
    ip_hdr->saddr = inet_addr(src_ip);
    ip_hdr->daddr = inet_addr(dst_ip);
    
    // Configurar cabeçalho ICMP
    icmp_hdr->type = type;
    icmp_hdr->code = code;
    icmp_hdr->un.echo.id = rand();
    icmp_hdr->un.echo.sequence = rand();
    icmp_hdr->checksum = 0;
    
    // Copiar payload
    if (payload && payload_len > 0) {
        memcpy(data, payload, payload_len);
    }
    
    // Calcular checksums
    icmp_hdr->checksum = calculate_icmp_checksum(icmp_hdr, sizeof(struct icmphdr) + payload_len);
    ip_hdr->check = calculate_ip_checksum(ip_hdr);
    
    return sizeof(struct iphdr) + sizeof(struct icmphdr) + payload_len;
}

// Funções de validação
int validate_ip_address(const char *ip) {
    struct in_addr addr;
    return inet_pton(AF_INET, ip, &addr) == 1;
}

int validate_port(int port) {
    return port >= 1 && port <= 65535;
}

int validate_packet_size(int size) {
    return size >= 0 && size <= 65535;
}

// Funções de debug
void print_packet_info(const char *packet, int size) {
    printf("[*] Pacote: %d bytes\n", size);
    
    if (size >= sizeof(struct iphdr)) {
        struct iphdr *ip_hdr = (struct iphdr *)packet;
        print_ip_header(ip_hdr);
        
        if (ip_hdr->protocol == IPPROTO_TCP && size >= sizeof(struct iphdr) + sizeof(struct tcphdr)) {
            struct tcphdr *tcp_hdr = (struct tcphdr *)(packet + sizeof(struct iphdr));
            print_tcp_header(tcp_hdr);
        } else if (ip_hdr->protocol == IPPROTO_UDP && size >= sizeof(struct iphdr) + sizeof(struct udphdr)) {
            struct udphdr *udp_hdr = (struct udphdr *)(packet + sizeof(struct iphdr));
            print_udp_header(udp_hdr);
        }
    }
}

void print_ip_header(const struct iphdr *ip_hdr) {
    char src_ip[16], dst_ip[16];
    
    inet_ntop(AF_INET, &(ip_hdr->saddr), src_ip, sizeof(src_ip));
    inet_ntop(AF_INET, &(ip_hdr->daddr), dst_ip, sizeof(dst_ip));
    
    printf("[*] IP: %s -> %s (TTL: %d, Protocol: %d)\n", 
           src_ip, dst_ip, ip_hdr->ttl, ip_hdr->protocol);
}

void print_tcp_header(const struct tcphdr *tcp_hdr) {
    printf("[*] TCP: %d -> %d (Flags: %s%s%s%s%s%s)\n",
           ntohs(tcp_hdr->source), ntohs(tcp_hdr->dest),
           tcp_hdr->fin ? "FIN " : "",
           tcp_hdr->syn ? "SYN " : "",
           tcp_hdr->rst ? "RST " : "",
           tcp_hdr->psh ? "PSH " : "",
           tcp_hdr->ack ? "ACK " : "",
           tcp_hdr->urg ? "URG" : "");
}

void print_udp_header(const struct udphdr *udp_hdr) {
    printf("[*] UDP: %d -> %d (Length: %d)\n",
           ntohs(udp_hdr->source), ntohs(udp_hdr->dest),
           ntohs(udp_hdr->len));
} 