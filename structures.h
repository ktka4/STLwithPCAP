#ifndef STRUCTURES_H
#define STRUCTURES_H

#include <vector>
#include "pcap.h"
#include <windows.h>

#define ETHER_ADDR_LEN 6

struct ethernet_header {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* Адрес хоста получателя*/
        u_char  ether_shost[ETHER_ADDR_LEN];    /* Адреc хоста отправителя */
        u_short ether_type;                     /* ТИП протокола (IP, ARP, RARP) */
};


typedef struct mac_address {
    u_char byte1;
    u_char byte2;
    u_char byte3;                     // 6 байт MAC-адресса
    u_char byte4;
 u_char byte5;
 u_char byte6;
}mac_address;



typedef struct ip_address{
    u_char byte1;
    u_char byte2;			// 4 байта адресса
    u_char byte3;
    u_char byte4;
}ip_address;


// 20 байт ip заголовка
typedef struct ip_header{
    u_char ver_ihl; // Version (4 bits) + Internet header length (4 bits)
    u_char tos; // Type of service
    u_short tlen; // Total length
    u_short identification; // Identification
    u_short flags_fo; // Flags (3 bits) + Fragment offset (13 bits)
    u_char ttl; // Time to live
    u_char proto; // Protocol
    u_short crc; // Header checksum
    ip_address saddr; // Source address
    ip_address daddr; // Destination address
 // u_int op_pad; // Option + Padding -- NOT NEEDED!
}ip_header;

// структура TCP заголовка
typedef struct tcp_header {
 u_short sport; // Source port
 u_short dport; // Destination port
 u_int seqnum; // Sequence Number
 u_int acknum; // Acknowledgement number
 u_char th_off; // Header length
 u_char flags; // packet flags
 u_short win; // Window size
 u_short crc; // Header Checksum
 u_short urgptr; // Urgent pointer...still don't know what this is...

}tcp_header;

//структура udp заголовка
typedef struct udp_header{
    u_short sport;          // Source port
    u_short dport;          // Destination port
    u_short len;            // Datagram length
    u_short crc;            // Checksum
}udp_header;

template <typename T>
inline void swapV( T & arg1, T & arg2)
{
    T temp = arg1;
    arg1 = arg2;
    arg2 = temp;
};


#endif // STRUCTURES_H
