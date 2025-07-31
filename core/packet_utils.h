/**
 * Packet Utils - Header
 * Utilitários para manipulação de pacotes de rede
 */

#ifndef PACKET_UTILS_H
#define PACKET_UTILS_H

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

// Funções de inicialização
int packet_utils_init(void);
void packet_utils_cleanup(void);

// Funções de checksum
unsigned short calculate_ip_checksum(struct iphdr *ip_hdr);
unsigned short calculate_tcp_checksum(struct iphdr *ip_hdr, struct tcphdr *tcp_hdr);
unsigned short calculate_udp_checksum(struct iphdr *ip_hdr, struct udphdr *udp_hdr);
unsigned short calculate_icmp_checksum(struct icmphdr *icmp_hdr, int len);

// Funções de manipulação de pacotes
int create_syn_packet(char *packet, const char *src_ip, const char *dst_ip, 
                    int src_port, int dst_port);
int create_udp_packet(char *packet, const char *src_ip, const char *dst_ip,
                     int src_port, int dst_port, const char *payload, int payload_len);
int create_icmp_packet(char *packet, const char *src_ip, const char *dst_ip,
                      int type, int code, const char *payload, int payload_len);

// Funções de validação
int validate_ip_address(const char *ip);
int validate_port(int port);
int validate_packet_size(int size);

// Funções de debug
void print_packet_info(const char *packet, int size);
void print_ip_header(const struct iphdr *ip_hdr);
void print_tcp_header(const struct tcphdr *tcp_hdr);
void print_udp_header(const struct udphdr *udp_hdr);

#endif // PACKET_UTILS_H 