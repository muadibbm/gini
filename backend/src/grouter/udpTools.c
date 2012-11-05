/*
 * ucpTools.c (tools using the UDP module)
 * AUTHOR: Alassane Ndiaye (260376319), Etienne Perot (260377858)
 */

#include "udp.h"
#include "udpTools.h"
#include "message.h"
#include <stdio.h>
#include <stdint.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>

pthread_t * udpServer = NULL;

void stopUDPServer() {
	pthread_cancel(*udpServer);
	printf("\n"); // Avoid the prompt being on the last line
}

void * runUDPServer(void * port) {
	uint16_t portNumber = *((uint16_t *) port);
	char * buffer;
	uint16_t sourcePort;
	uint16_t length;
	uchar source[4];
	uchar destination[4];
	char * printableSource = (char *) malloc(16);
	printf("[UDPServer @ %d] Receiving thread spawned.\n", portNumber);
	while(1) {
		receive_udp(portNumber, destination, source, &sourcePort, &buffer, &length);
		printf("[UDPServer @ %d] Received a packet on port %d:\n", portNumber, portNumber);
		printf("[UDPServer @ %d] - Sent by: %s\n", portNumber, IP2Dot(printableSource, source));
		printf("[UDPServer @ %d] - Source port: %i\n", portNumber, sourcePort);
		printf("[UDPServer @ %d] - Packet length: %i bytes\n", portNumber, length);
		printf("[UDPServer @ %d] - Packet contents:\n", portNumber);
		prettyPrint(buffer, length);
		printf("\n[UDPServer @ %d] End of packet.\n", portNumber);
		printf("[UDPServer @ %d] ---------------------------------------\n", portNumber);
	}
}

void startUDPServer(uint16_t portNumber) {
	// Rebind signals to top the server
	redefineSignalHandler(SIGINT, stopUDPServer);
	redefineSignalHandler(SIGQUIT, stopUDPServer);
	redefineSignalHandler(SIGTSTP, stopUDPServer);
	if(udpServer != NULL) {
		free(udpServer);
	}
	if(listen_udp(portNumber) != EXIT_SUCCESS) {
		printf("[UDPServer @ %d] Cannot start UDP server on port %d.\n", portNumber, portNumber);
	} else {
		udpServer = (pthread_t *) malloc(sizeof(pthread_t));
		pthread_create(udpServer, NULL, &runUDPServer, (void *) &portNumber);
		pthread_join(*udpServer, NULL);
		close_udp(portNumber);
	}
}

void sendUDPPacket(uint16_t sourcePortNumber, uchar * destination, uint16_t destinationPortNumber, char * contents) {
	if(send_udp(sourcePortNumber, destination, destinationPortNumber, contents, strlen(contents)) == EXIT_SUCCESS) {
		printf("[sendUDPPacket] Sent UDP packet.\n");
	} else {
		printf("[sendUDPPacket] Failed to send UDP packet.\n");
	}
}