/*
 * ucp.c (collection of functions that implement UDP)
 * AUTHOR: Alassane Ndiaye (260376319), Etienne Perot (260377858)
 */

#include "protocols.h"
#include "icmp.h"
#include "ip.h"
#include "udp.h"
#include "message.h"
#include "grouter.h"
#include <slack/err.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

udp_service_t * udpServices[USHRT_MAX];

void UDPInit() {
	int i;
	for(i = 0; i < USHRT_MAX; i++) {
		udpServices[i] = NULL;
	}
}

void UDPDeinit() {
	int i;
	for(i = 0; i < USHRT_MAX; i++) {
		if(udpServices[i] != NULL) {
			destroySimpleQueue(udpServices[i]->queue);
			free(udpServices[i]);
		}
	}
}

typedef struct _udp_checksummable_packet
{
	uchar source[4];
	uchar destination[4];
	uchar zeroes;
	uchar protocol;
	uint16_t length;
} udp_checksummable_packet;

uint16_t UDPChecksum(ip_packet_t * ip_packet)
{
	udp_header_t * udp_header = (udp_header_t *) (((uchar *) ip_packet) + ip_packet->ip_hdr_len * 4);
	uint16_t udpLength = ntohs(udp_header->length);
	uint16_t udpLengthPad = udpLength;
	if (udpLengthPad & 1) { // If length is odd
		udpLengthPad++;
	}
	udp_checksummable_packet * checksummable = calloc(sizeof(udp_checksummable_packet) + udpLengthPad, 1);
	memcpy(checksummable->source, ip_packet->ip_src, 8); // Copies both ip_src and ip_dst
	checksummable->zeroes = 0;
	checksummable->protocol = UDP_PROTOCOL;
	checksummable->length = udp_header->length;
	memcpy(checksummable + 1, udp_header, udpLength);
	udp_header_t * copied_udp_header = (udp_header_t *) (checksummable + 1);
	// Make sure the checksum field (that previously was in the packet) is empty
	copied_udp_header->checksum = 0;
	uint16_t result = checksum((uchar *) checksummable, (sizeof(udp_checksummable_packet) + udpLengthPad) / 2);
	free(checksummable);
	return result;
}

int listen_udp(uint16_t port) {
	if(!port || udpServices[port] != NULL) {
		return EXIT_FAILURE; // Port already in use
	}
	udpServices[port] = (udp_service_t *) malloc(sizeof(udp_service_t));
	udpServices[port]-> queue = createSimpleQueue("UDP service", INFINITE_Q_SIZE, 0, 1);
	verbose(2, "[listen_udp]:: Now listening on port %i...", port);
	return EXIT_SUCCESS;
}

int close_udp(uint16_t port) {
	if(!port || udpServices[port] == NULL) {
		return EXIT_FAILURE; // Port wasn't in use in the first place
	}
	destroySimpleQueue(udpServices[port]->queue);
	free(udpServices[port]);
	udpServices[port] = NULL;
	verbose(2, "[listen_udp]:: Closed port %i.", port);
	return EXIT_SUCCESS;
}

int receive_udp(uint16_t port, uchar * destination, uchar * source, uint16_t * sourcePort, char ** buffer, uint16_t * length) {
	if(!port || udpServices[port] == NULL) {
		return EXIT_FAILURE; // Not listening on port
	}
	verbose(2, "[receive_udp]:: Received packet for port %i.", port);
	udp_packet_t * packet = (udp_packet_t *) malloc(sizeof(udp_packet_t));
	void * data;
	int size;
	readQueue(udpServices[port]->queue, &data, &size);
	memcpy(packet, data, size);
	memcpy(source, packet->source, 4);
	memcpy(destination, packet->destination, 4);
	char * copyBuffer = (char *) malloc(packet->header.length);
	memcpy(copyBuffer, packet->data, packet->header.length);
	*sourcePort = packet->header.sourcePort;
	*buffer = copyBuffer;
	*length = packet->header.length;
	freeUDPPacket(packet);
	return EXIT_SUCCESS;
}

int send_udp(uint16_t sourcePort, uchar * dest, uint16_t port, char * data, uint16_t length) {
	if(!port) {
		return EXIT_FAILURE;
	}
	gpacket_t * packet = (gpacket_t *) calloc(sizeof(gpacket_t), 1);
	ip_packet_t * ip_packet = (ip_packet_t *) (packet->data.data);
	ip_packet->ip_hdr_len = 5;
	udp_header_t * udp_header = (udp_header_t *) (((char *) ip_packet) + ip_packet->ip_hdr_len * 4);
	udp_header->sourcePort = htons(sourcePort);
	udp_header->destinationPort = htons(port);
	udp_header->length = htons(length + UDP_HEADER_SIZE);
	udp_header->checksum = htons(0); // Temporary, will compute it later
	memcpy(udp_header + 1, data, length);
	// We need to populate the ip_src field before we can compute the UDP checksum
	if(IPPreparePacket(packet, dest, length + UDP_HEADER_SIZE, 1, UDP_PROTOCOL) != EXIT_SUCCESS) {
		return EXIT_FAILURE;
	}
	// Now compute the checksum
	uint16_t checksum = UDPChecksum(ip_packet);
	udp_header->checksum = htons(checksum);
	// And finally send
	return IPOutgoingPacketChecksumAndSend(packet, dest, length + UDP_HEADER_SIZE, 1, UDP_PROTOCOL);
}

void printParsedUDPPacket(udp_packet_t * packet) {
	udp_header_t * header = &(packet->header);
	char * data = packet->data;
	printf("~ Source: %d.%d.%d.%d on port %i\n", (int) packet->source[0], (int) packet->source[1], (int) packet->source[2], (int) packet->source[3], header->sourcePort);
	printf("~ Destination: %d.%d.%d.%d on port %i\n", (int) packet->destination[0], (int) packet->destination[1], (int) packet->destination[2], (int) packet->destination[3], header->destinationPort);
	printf("~ Packet length: %i bytes\n", header->length);
	printf("~ Checksum: %i\n", header->checksum);
	printf("~ Packet contents:\n");
	prettyPrint(data, header->length);
	printf("\n~ End of packet.\n");
}

int UDPProcess(gpacket_t * in_pkt)
{
	verbose(2, "[UDPProcess]:: packet received for processing...");
	udp_packet_t * packet;
	if(parseUDPPacket(in_pkt, &packet) != EXIT_SUCCESS) {
		return EXIT_FAILURE;
	}
	if(udpServices[packet->header.destinationPort] != NULL) {
		// Handle the packet
		writeQueue(udpServices[packet->header.destinationPort]->queue, packet, sizeof(udp_packet_t));
	} else {
		// Drop the packet
		freeUDPPacket(packet);
	}
	return EXIT_SUCCESS;
}

void freeUDPPacket(udp_packet_t * packet) {
	free(packet->data);
	free(packet);
}

int parseUDPPacket(gpacket_t * in_pkt, udp_packet_t ** out_pkt) {
	verbose(3, "[UDPProcess]:: Parsing requested for packet...");
	udp_packet_t * packet = (udp_packet_t *) malloc(sizeof(udp_packet_t));
	ip_packet_t * ip_packet = (ip_packet_t *) in_pkt->data.data;
	int ip_header_length = ip_packet->ip_hdr_len * 4;
	udp_header_t * udp_header = (udp_header_t *) malloc(UDP_HEADER_SIZE);
	memcpy(udp_header, ((char *) ip_packet) + ip_header_length, UDP_HEADER_SIZE);
	udp_header->sourcePort = ntohs(udp_header->sourcePort);
	udp_header->destinationPort = ntohs(udp_header->destinationPort);
	udp_header->length = ntohs(udp_header->length) - UDP_HEADER_SIZE;
	udp_header->checksum = ntohs(udp_header->checksum);
	char * buffer = (char *) malloc(udp_header->length);
	memcpy(buffer, ((char *) ip_packet) + ip_header_length + UDP_HEADER_SIZE, udp_header->length);
	gNtohl(packet->source, ip_packet->ip_src);
	gNtohl(packet->destination, ip_packet->ip_dst);
	// Handle the checksum
	if(udp_header->checksum == 0) {
		// Checksum not specified, skip
		verbose(3, "[UDPProcess]:: Packet checksum is 0; skipping checksum computation.");
	} else {
		// Actually compute it
		uint16_t computedChecksum = UDPChecksum(ip_packet); // Now compute it
		if(udp_header->checksum != computedChecksum) {
			verbose(3, "[UDPProcess]:: Packet checksums don't match!");
			verbose(3, "[UDPProcess]:: Contained checksum is %x (%d).", udp_header->checksum, udp_header->checksum);
			verbose(3, "[UDPProcess]:: Computed checksum is %x (%d).", computedChecksum, computedChecksum);
			free(udp_header);
			return EXIT_FAILURE;
		} else {
			verbose(3, "[UDPProcess]:: Checksums match %x (%d).", computedChecksum, computedChecksum);
		}
	}
	packet->header = *udp_header;
	packet->data = buffer;
	*out_pkt = packet;
	return EXIT_SUCCESS;
}