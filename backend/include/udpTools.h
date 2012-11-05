/*
 * udpTools.h (header file for the UDP tools)
 * AUTHOR: Alassane Ndiaye (260376319), Etienne Perot (260377858)
 */

#ifndef __UDPTOOLS_H_
#define __UDPTOOLS_H_

#include <sys/types.h>
#include <stdint.h>
#include "udp.h"

void * runUDPServer(void * port);

void startUDPServer(uint16_t portNumber);
void sendUDPPacket(uint16_t sourcePortNumber, uchar * destination, uint16_t destinationPortNumber, char * contents);

#endif
