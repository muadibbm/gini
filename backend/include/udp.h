/*
 * udp.h (header file for the UDP module)
 * AUTHOR: Alassane Ndiaye (260376319), Etienne Perot (260377858)
 */

#ifndef __UDP_H_
#define __UDP_H_

#include <sys/types.h>
#include <stdint.h>
#include "grouter.h"
#include "message.h"
#include "simplequeue.h"

typedef struct _udp_header_t
{
	uint16_t sourcePort;
	uint16_t destinationPort;
	uint16_t length;
	uint16_t checksum;
} udp_header_t;

typedef struct _udp_packet_t
{
	udp_header_t header;
	uchar source[4];
	uchar destination[4];
	char * data;
} udp_packet_t;

typedef struct _udp_service_t
{
	simplequeue_t * queue;
} udp_service_t;

#define UDP_HEADER_SIZE (sizeof(udp_header_t))


void UDPInit();
void UDPDeinit();
int UDPProcess(gpacket_t *in_pkt);
int parseUDPPacket(gpacket_t * in_pkt, udp_packet_t ** out_pkt);
void printParsedUDPPacket(udp_packet_t * packet);
void freeUDPPacket(udp_packet_t * packet);

int send_udp(uint16_t sourcePort, uchar * dest, uint16_t port, char * data, uint16_t length);
int listen_udp(uint16_t port);
int close_udp(uint16_t port);
int receive_udp(uint16_t port, uchar * destination, uchar * source, uint16_t * sourcePort, char ** buffer, uint16_t * length);

#endif
