/*
 * ip.c (collection of functions that implement the IP (Internet protocol).
 * AUTHOR: Original version by Weiling Xu
 *         Revised by Muthucumaru Maheswaran
 * DATE:   Last revised on June 22, 2008
 */

#include "message.h"
#include "grouter.h"
#include "routetable.h"
#include "mtu.h"
#include "protocols.h"
#include "ip.h"
#include "fragment.h"
#include "packetcore.h"
#include "udp.h"
#include <stdlib.h>
#include <slack/err.h>
#include <netinet/in.h>
#include <string.h>

route_entry_t route_tbl[MAX_ROUTES];       	// routing table
mtu_entry_t MTU_tbl[MAX_MTU];		        // MTU table
uchar igmp_bcast_mac[] = MAC_IGMP_BCAST_ADDR;

extern pktcore_t *pcore;

void IPInit() {
	RouteTableInit(route_tbl);
	MTUTableInit(MTU_tbl);
	UDPInit();
}

void IPDeinit() {
	UDPDeinit();
}

/*
 * IPIncomingPacket: Process incoming IP packet.
 * The IP packet can be destined to the local router (for example route updates).
 * Or it could be a packet meant for forwarding: either unicast or multicast/broadcast.
 * This is a wrapper routine that calls the appropriate subroutine to take
 * the appropriate function.
 */
void IPIncomingPacket(gpacket_t *in_pkt) {
	char tmpbuf[MAX_TMPBUF_LEN];
	// get a pointer to the IP packet
	ip_packet_t *ip_pkt = (ip_packet_t *) &in_pkt->data.data;
	uchar bcast_ip[] = IP_BCAST_ADDR;
	int mcast_ip = IP_MCAST_ADDR;

	verbose(1, "GUY TEST: ip_pkt->ip_prot  %d", ip_pkt->ip_prot);

	// Is this IP packet for me??
	if (ip_pkt->ip_prot == IGMP_PROTOCOL) {
		// Is packet IGMP? send it to the IGMP module
		// further processing with appropriate type code
		IGMP_RCV(in_pkt);

	} else if (IPCheckPacket4Me(in_pkt)) {
		verbose(2,
				"[IPIncomingPacket]:: got IP packet destined to this router");
		IPProcessMyPacket(in_pkt);
	} else if (COMPARE_IP(gNtohl(tmpbuf, ip_pkt->ip_dst), bcast_ip) == 0) {
		// TODO: rudimentary 'broadcast IP address' check
		verbose(2,
				"[IPIncomingPacket]:: not repeat broadcast (final destination %s), packet thrown",
				IP2Dot(tmpbuf, gNtohl((tmpbuf + 20), ip_pkt->ip_dst)));
		IPProcessBcastPacket(in_pkt);
	} else if (((((int) ip_pkt->ip_dst[0]) >> 4) << 4) == mcast_ip) {
		//If the IP starts with 1110 we have a multicast IP. NOTE: this must be after IGMP check since they have the same IP range.
		IPProcessMcastPacket(in_pkt);
	} else {
		// Destinated to someone else
		verbose(2,
				"[IPIncomingPacket]:: got IP packet destined to someone else");
		IPProcessForwardingPacket(in_pkt);
	}
}

/*
 * IPCheckPacket4Me: Return TRUE if the packet is meant for me. Otherwise return FALSE.
 * Check against all possible IPs I have to determine whether this packet
 * is meant for me.
 */
int IPCheckPacket4Me(gpacket_t *in_pkt) {
	ip_packet_t *ip_pkt = (ip_packet_t *) &in_pkt->data.data;
	char tmpbuf[MAX_TMPBUF_LEN];
	int count, i;
	uchar iface_ip[MAX_MTU][4];
	uchar pkt_ip[4];

	COPY_IP(pkt_ip, gNtohl(tmpbuf, ip_pkt->ip_dst));
	verbose(2, "[IPCheckPacket4Me]:: looking for IP %s ",
			IP2Dot(tmpbuf, pkt_ip));
	if ((count = findAllInterfaceIPs(MTU_tbl, iface_ip)) > 0) {
		for (i = 0; i < count; i++) {
			if (COMPARE_IP(iface_ip[i], pkt_ip) == 0) {
				verbose(2, "[IPCheckPacket4Me]:: found a matching IP.. for %s ",
						IP2Dot(tmpbuf, pkt_ip));
				return TRUE;
			}
		}
		return FALSE;
	} else
		return FALSE;
}

int IPProcessMcastPacket(gpacket_t *in_pkt) {
	gpacket_t *pkt_frags[MAX_FRAGMENTS];
	ip_packet_t *ip_pkt = (ip_packet_t *) in_pkt->data.data;
	int num_frags, i, need_frag;
	char tmpbuf[MAX_TMPBUF_LEN];

	// Checks to make sure we arent in the range 224.0.0.0 and 224.0.0.255
	// This is a reserved range .
	if (ip_pkt->ip_dst[0] == 224 && ip_pkt->ip_dst[1] == 0
			&& ip_pkt->ip_dst[2] == 0) {
		verbose(2, "[IPProcessMcastPacket]  Can't send to a reserved space.");
		return EXIT_FAILURE;

	}

//	TODO: checkMultiCastPacket for errors etc;

	// TODO: send to other routers as well.

	// Forward to hosts
	verbose(1, "GUY TEST FORWARD HOSTS");
	int forward_interface = IGMP_GetGroupInterfaces(in_pkt);
	if (forward_interface != -1) {
		verbose(1, "GUY TEST interface forward");
		gpacket_t *out_pkt = (gpacket_t *) malloc(sizeof(gpacket_t));
		memcpy(out_pkt, in_pkt, sizeof(*in_pkt));
		out_pkt ->frame.dst_interface = forward_interface;

		if (IPSend2Output(out_pkt ) == EXIT_FAILURE) {
			return EXIT_FAILURE;
		}

	} else {
		verbose(2,
				"[IPProcessMcastPacket]: We don't have hosts in that group");
	}

	// Forward to routers

	verbose(1, "GUY TEST FORWARD ROUTERS");
	// look through the pair table. Get the subnets that we care about
	verbose(1,"[GUY TEST -1.0]: IGMPGetGroupSubnets");
	List *subnetList = IGMPGetGroupSubnets(in_pkt);

	List *hopList = list_create(NULL);

	// find those subnets in our route table and remove duplicates


	// send to all neighbours by trying all entries in the router.
	if (subnetList != NULL) {
		// Go through all the subnet and route table
		while (list_has_next(subnetList)) {
			int nextItem = (int) list_next(subnetList);

			int index_t = 0;
			while (index_t < MAX_ROUTES) {
				if (route_tbl[index_t].is_empty == 0) {

					// check the subnet to see if this one is the entry.
					if (route_tbl[index_t].network[1] == nextItem) {

						// figure out if we already added the hop.
						int found = 0;
						while (list_has_next(hopList)) {
							int nextItem2 = (int) list_next(hopList);

							if (index_t == nextItem2) {
								found = 1;
							}

						}

						if (found == 0) {
							list_append_int(hopList, index_t);
						}
					}
				}

				index_t++;
			}
		}
	}

	while (list_has_next(hopList)) {
		int nextItem3 = (int) list_next(hopList);

		int forward_index = nextItem3;

		if (forward_index != -1) {

			gpacket_t *out_pkt = (gpacket_t *) malloc(sizeof(gpacket_t));
			memcpy(out_pkt, in_pkt, sizeof(*in_pkt));

			COPY_IP(out_pkt->frame.nxth_ip_addr,route_tbl[forward_index].nexthop);
			verbose(1,"[GUY TEST 2.3] ntxhp ip %d %d %d %d ", out_pkt->frame.nxth_ip_addr[0],out_pkt->frame.nxth_ip_addr[1],out_pkt->frame.nxth_ip_addr[2],out_pkt->frame.nxth_ip_addr[3]);
			out_pkt->frame.dst_interface = route_tbl[forward_index].interface;

			ip_packet_t *out_ip_pkt = (ip_packet_t *) out_pkt->data.data;

			verbose(1,"[GUY TEST 2.3] dst ip is  %d %d %d %d ", out_ip_pkt->ip_dst[0],out_ip_pkt->ip_dst[1],out_ip_pkt->ip_dst[2],out_ip_pkt->ip_dst[3]);
			verbose(1,"[GUY TEST 2.3] src ip is  %d %d %d %d ", out_ip_pkt->ip_src[0],out_ip_pkt->ip_src[1],out_ip_pkt->ip_src[2],out_ip_pkt->ip_src[3]);

			if (IPSend2Output(out_pkt) == EXIT_FAILURE) {
				verbose(1,"[GUY TEST 2.3]");
				return EXIT_FAILURE;
			}
			verbose(1,"[GUY TEST 2.3.1]");

		} else {
			verbose(1,"[GUY TEST 2.4]");
			verbose(2,
					"[IPProcessMcastPacket]: We don't have routers in that group");
		}

	}

	verbose(1,"[GUY TEST 2.5]");
	//send to the next hop.
	return EXIT_SUCCESS;
}

/*
 * TODO: broadcast not yet implemented.. should be simple to implement.
 * read RFC 1812 and 922 ...
 */
int IPProcessBcastPacket(gpacket_t *in_pkt) {
	return EXIT_SUCCESS;
}

/*
 * Sends an IP packet destined to someone in a group.
 * This is based on the Normal ProcessForwardingPacket.
 * It is specifcially implemented for the in-complete Multicast packet.
 * It adds checksum and interface information etc....
 */

int ProcessForwardingMulticastPacket(gpacket_t *in_pkt) {

	gpacket_t *pkt_frags[MAX_FRAGMENTS];
	ip_packet_t *ip_pkt = (ip_packet_t *) in_pkt->data.data;
	int num_frags, i, need_frag;
	char tmpbuf[MAX_TMPBUF_LEN];

// TODO: make the checksums work so that this IPCheck is called. It could be useful.
	/*
	 if (IPCheck4Errors(in_pkt) == EXIT_FAILURE)
	 {
	 verbose(1, "GUY TEST: 5.2  IPCheck4Errors failed");
	 return EXIT_FAILURE;
	 }
	 */

// find the route... if it does not exist, should we send a
// ICMP network/host unreachable message -- CHECK??
	if (findRouteEntry(route_tbl, gNtohl(tmpbuf, ip_pkt->ip_dst),
			in_pkt->frame.nxth_ip_addr, &(in_pkt->frame.dst_interface))
			== EXIT_FAILURE) {
		return EXIT_FAILURE;
	}

// check for redirection?? -- the output interface is already found
// by the previous command.. if needed the following routine sends the
// redirects but the packet is sent to destination..
// TODO: Check the RFC for conformance??
	IPCheck4Redirection(in_pkt);

// check for fragmentation -- this should return three conditions:
// FRAGS_NONE, FRAGS_ERROR, MORE_FRAGS
	need_frag = IPCheck4Fragmentation(in_pkt);

	switch (need_frag) {
	case FRAGS_NONE:
		verbose(2, "[IPProcessForwardingPacket]:: sending packet to GNET..");
// compute the checksum before sending out.. the fragmentation routine does this inside it.
		ip_pkt->ip_cksum = 0;
		ip_pkt->ip_cksum = htons(
				checksum((uchar *) ip_pkt, ip_pkt->ip_hdr_len * 2));
		if (IPSend2Output(in_pkt) == EXIT_FAILURE) {
			return EXIT_FAILURE;
		}
		break;

	case FRAGS_ERROR:
		verbose(2,
				"[IPProcessForwardingPacket]:: unreachable on packet from %s",
				IP2Dot(tmpbuf, gNtohl((tmpbuf + 20), ip_pkt->ip_src)));
		ICMPProcessFragNeeded(in_pkt);
		break;

	case MORE_FRAGS:

// fragment processing...
		num_frags = fragmentIPPacket(in_pkt, pkt_frags);

		verbose(2,
				"[IPProcessForwardingPacket]:: IP packet needs fragmentation");
// forward each fragment
		for (i = 0; i < num_frags; i++) {
			if (IPSend2Output(pkt_frags[i]) == EXIT_FAILURE) {
				verbose(2,
						"[IPProcessForwardingPacket]:: processForwardIPPacket(): Could not forward packets ");
				return EXIT_FAILURE;
			}
		}
		deallocateFragments(pkt_frags, num_frags);
		break;
	default:
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;

}

/*
 * process an IP packet destined to someone else...
 * ARGUMENT: in_pkt - pointer to incoming packet
 *
 * Error processing: Check for conditions that generate ICMP packets.
 * For example, TTL expired, redirect, malformed packets, ...
 * DF set and fragment,.. etc.
 *
 * Fragment processing: Check whether fragment is necessary .. condition already checked.
 *
 * Forward packet and fragments (could be multicasting)
 */
int IPProcessForwardingPacket(gpacket_t *in_pkt) {

	gpacket_t *pkt_frags[MAX_FRAGMENTS];
	ip_packet_t *ip_pkt = (ip_packet_t *) in_pkt->data.data;
	int num_frags, i, need_frag;
	char tmpbuf[MAX_TMPBUF_LEN];

	verbose(2, "[IPProcessForwardingPacket]:: checking for any IP errors..");
// all the validation and ICMP generation, processing is
// done in this function...

	if (IPCheck4Errors(in_pkt) == EXIT_FAILURE) {
		return EXIT_FAILURE;
	}

// find the route... if it does not exist, should we send a
// ICMP network/host unreachable message -- CHECK??
	if (findRouteEntry(route_tbl, gNtohl(tmpbuf, ip_pkt->ip_dst),
			in_pkt->frame.nxth_ip_addr, &(in_pkt->frame.dst_interface))
			== EXIT_FAILURE) {
		return EXIT_FAILURE;
	}

// check for redirection?? -- the output interface is already found
// by the previous command.. if needed the following routine sends the
// redirects but the packet is sent to destination..
// TODO: Check the RFC for conformance??
	IPCheck4Redirection(in_pkt);

// check for fragmentation -- this should return three conditions:
// FRAGS_NONE, FRAGS_ERROR, MORE_FRAGS
	need_frag = IPCheck4Fragmentation(in_pkt);

	switch (need_frag) {
	case FRAGS_NONE:
		verbose(2, "[IPProcessForwardingPacket]:: sending packet to GNET..");
// compute the checksum before sending out.. the fragmentation routine does this inside it.
		ip_pkt->ip_cksum = 0;
		ip_pkt->ip_cksum = htons(
				checksum((uchar *) ip_pkt, ip_pkt->ip_hdr_len * 2));
		if (IPSend2Output(in_pkt) == EXIT_FAILURE) {
			verbose(1,
					"[IPProcessForwardingPacket]:: WARNING: IPProcessForwardingPacket(): Could not forward packets ");
			return EXIT_FAILURE;
		}
		break;

	case FRAGS_ERROR:
		verbose(2,
				"[IPProcessForwardingPacket]:: unreachable on packet from %s",
				IP2Dot(tmpbuf, gNtohl((tmpbuf + 20), ip_pkt->ip_src)));
		ICMPProcessFragNeeded(in_pkt);
		break;

	case MORE_FRAGS:
// fragment processing...
		num_frags = fragmentIPPacket(in_pkt, pkt_frags);

		verbose(2,
				"[IPProcessForwardingPacket]:: IP packet needs fragmentation");
// forward each fragment
		for (i = 0; i < num_frags; i++) {
			if (IPSend2Output(pkt_frags[i]) == EXIT_FAILURE) {
				verbose(1,
						"[IPProcessForwardingPacket]:: processForwardIPPacket(): Could not forward packets ");
				return EXIT_FAILURE;
			}
		}
		deallocateFragments(pkt_frags, num_frags);
		break;
	default:
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

int IGMPCheck4Errors(gpacket_t *in_pkt) {
	char tmpbuf[MAX_TMPBUF_LEN];

	ip_packet_t *ip_pkt = (ip_packet_t *) in_pkt->data.data;

// check for valid version and checksum.. silently drop the packet if not.
	if (IPVerifyPacket(ip_pkt) == EXIT_FAILURE) {
		verbose(2, "[IGMPCheck4Errors]:: IPVerifyPacket failed for %s",
				IP2Dot(tmpbuf, gNtohl((tmpbuf + 20), ip_pkt->ip_src)));
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

int IPCheck4Errors(gpacket_t *in_pkt) {
	char tmpbuf[MAX_TMPBUF_LEN];

	ip_packet_t *ip_pkt = (ip_packet_t *) in_pkt->data.data;

// check for valid version and checksum.. silently drop the packet if not.
	if (IPVerifyPacket(ip_pkt) == EXIT_FAILURE) {
		return EXIT_FAILURE;
	}

// Decrement TTL, if TTL <= 0, send to ICMP module with TTL-expired command
// return EXIT_FAILURE

	if (--ip_pkt->ip_ttl <= 0) {
		verbose(2, "[processIPErrors]:: TTL expired on packet from %s",
				IP2Dot(tmpbuf, gNtohl((tmpbuf + 20), ip_pkt->ip_src)));

		ICMPProcessTTLExpired(in_pkt);
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

/*
 * check for MTU sizes and DF flag..
 * first get the MTU value for the next hop interface.
 * if the current packet size is greater than the next hop MTU, then
 * fragmentation is needed. If the DF is set and fragmentation is
 * needed, an error condition occurs.
 * FRAGS_NONE - no fragmentation;
 * FRAGS_ERROR - fragmentation error;
 * MORE_FRAGS - fragmentation is required.
 * GENERAL_ERROR - mtu not found.
 */
int IPCheck4Fragmentation(gpacket_t *in_pkt) {
	int link_mtu;
	char tmpbuf[MAX_TMPBUF_LEN];
	ip_packet_t *ip_pkt = (ip_packet_t *) in_pkt->data.data;

	verbose(2,
			"[IPCheck4Fragmentation]:: .. checking mtu for next hop %s and interface %d ",
			IP2Dot(tmpbuf, in_pkt->frame.nxth_ip_addr),
			in_pkt->frame.dst_interface);

	if ((link_mtu = findMTU(MTU_tbl, in_pkt->frame.dst_interface)) < 0)
		return GENERAL_ERROR;

	if (link_mtu < ntohs(ip_pkt->ip_pkt_len))              // need fragmentation
			{
		if (TEST_DF_BITS(ip_pkt->ip_frag_off)) // DF is set: destination unreachable
			return FRAGS_ERROR;
		return MORE_FRAGS;
	} else
		return FRAGS_NONE;
}

/*
 * check for redirection condition. This function always returns
 * success. That is no matter whether redirection was sent or not
 * it returns success!
 */
int IPCheck4Redirection(gpacket_t *in_pkt) {
	char tmpbuf[MAX_TMPBUF_LEN];
	gpacket_t *cp_pkt;
	ip_packet_t *ip_pkt = (ip_packet_t *) in_pkt->data.data;

// check for redirect condition and send an ICMP back... let the current packet
// go as well (check the specification??)
	if (isInSameNetwork(gNtohl(tmpbuf, ip_pkt->ip_src),
			in_pkt->frame.nxth_ip_addr) == EXIT_SUCCESS) {
		verbose(2,
				"[processIPErrors]:: redirect message sent on packet from %s",
				IP2Dot(tmpbuf, gNtohl((tmpbuf + 20), ip_pkt->ip_src)));

		cp_pkt = duplicatePacket(in_pkt);

		ICMPProcessRedirect(cp_pkt, cp_pkt->frame.nxth_ip_addr);
	}

// IP packet is verified to be good. This packet should be
// further processed to carry out forwarding.
	return EXIT_SUCCESS;
}

/*
 * process an IP packet destined to the router itself
 * ARGUMENT: in_pkt points to the message containing the packet
 * RETURNS: EXIT_FAILURE or EXIT_SUCCESS;
 *
 * Processing flow is as follows:
 *      Error processing: A similar routine as the "forwarding mode"
 *      Control packet processing: ICMP processing.. send it to the
 *                                 ICMP module which is going to decode the
 *                                 packet further.
 *      Information packet processing: These are UDP/TCP packets destined
 *                                 to the router. They contain route
 *                                 updates.. mainly driven by routing algorithms
 */
int IPProcessMyPacket(gpacket_t *in_pkt) {
	ip_packet_t *ip_pkt = (ip_packet_t *) in_pkt->data.data;

	if (IPVerifyPacket(ip_pkt) == EXIT_SUCCESS) {
// Is packet ICMP? send it to the ICMP module
// further processing with appropriate type code
		if (ip_pkt->ip_prot == ICMP_PROTOCOL)
			ICMPProcessPacket(in_pkt);
// Is packet UDP/TCP (only UDP implemented now)
// May be we can deal with other connectionless protocols as well.
		if (ip_pkt->ip_prot == UDP_PROTOCOL)
			UDPProcess(in_pkt);
		return EXIT_SUCCESS;
	}
	return EXIT_FAILURE;
}

int IPPreparePacket(gpacket_t *pkt, uchar *dst_ip, int size, int newflag,
		int src_prot) {
	ip_packet_t *ip_pkt = (ip_packet_t *) pkt->data.data;
	char tmpbuf[MAX_TMPBUF_LEN];
	uchar iface_ip_addr[4];
	int status;
	ip_pkt->ip_ttl = 64;                        // set TTL to default value
	ip_pkt->ip_cksum = 0;                       // reset the checksum field
	ip_pkt->ip_prot = ICMP_PROTOCOL;  // set the protocol field
	if (newflag == 0) {
		COPY_IP(ip_pkt->ip_dst, ip_pkt->ip_src);
// set dst to original src
		COPY_IP(ip_pkt->ip_src, gHtonl(tmpbuf, pkt->frame.src_ip_addr));
// set src to me

// find the nexthop and interface and fill them in the "meta" frame
// NOTE: the packet itself is not modified by this lookup!
		if (findRouteEntry(route_tbl, gNtohl(tmpbuf, ip_pkt->ip_dst),
				pkt->frame.nxth_ip_addr, &(pkt->frame.dst_interface))
				== EXIT_FAILURE) {
			verbose(2,
					"[IPOutgoingPacket]:: findRouteEntry failed (newflag = 0)");
			return EXIT_FAILURE;
		}
	} else if (newflag == 1) {
// non REPLY PACKET -- this is a new packet; set all fields
		ip_pkt->ip_version = 4;
		ip_pkt->ip_hdr_len = 5;
		ip_pkt->ip_tos = 0;
		ip_pkt->ip_identifier = IP_OFFMASK & random();
		RESET_DF_BITS(ip_pkt->ip_frag_off);
		RESET_MF_BITS(ip_pkt->ip_frag_off);
		ip_pkt->ip_frag_off = 0;

		COPY_IP(ip_pkt->ip_dst, gHtonl(tmpbuf, dst_ip));
		ip_pkt->ip_pkt_len = htons(size + ip_pkt->ip_hdr_len * 4);

		verbose(2, "[IPOutgoingPacket]:: lookup next hop ");
// find the nexthop and interface and fill them in the "meta" frame
// NOTE: the packet itself is not modified by this lookup!
		if (findRouteEntry(route_tbl, gNtohl(tmpbuf, ip_pkt->ip_dst),
				pkt->frame.nxth_ip_addr, &(pkt->frame.dst_interface))
				== EXIT_FAILURE) {
			verbose(2,
					"[IPOutgoingPacket]:: findRouteEntry failed (newflag = 1)");
			return EXIT_FAILURE;
		}
		verbose(2, "[IPOutgoingPacket]:: lookup MTU of nexthop");
// lookup the IP address of the destination interface..
		if ((status = findInterfaceIP(MTU_tbl, pkt->frame.dst_interface,
				iface_ip_addr)) == EXIT_FAILURE)
			return EXIT_FAILURE;
// the outgoing packet should have the interface IP as source
		COPY_IP(ip_pkt->ip_src, gHtonl(tmpbuf, iface_ip_addr));
		verbose(2,
				"[IPOutgoingPacket]:: almost done processing the IP header.");
	} else {
		error(
				"[IPOutgoingPacket]:: unknown outgoing packet action.. packet discarded ");
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

int IGMPPreparePacket(gpacket_t *pkt, uchar *dst_ip, int size, int newflag,
		int src_prot) {
	ip_packet_t *ip_pkt = (ip_packet_t *) pkt->data.data;
	char tmpbuf[MAX_TMPBUF_LEN];
	uchar iface_ip_addr[4];
	int status;
	ip_pkt->ip_ttl = 1;                        // set TTL to default value
	ip_pkt->ip_cksum = 0;                       // reset the checksum field
	ip_pkt->ip_prot = IGMP_PROTOCOL;  // set the protocol field
	if (newflag == 0) {
		COPY_IP(ip_pkt->ip_dst, ip_pkt->ip_src);
// set dst to original src
		COPY_IP(ip_pkt->ip_src, gHtonl(tmpbuf, pkt->frame.src_ip_addr));
// set src to me

// find the nexthop and interface and fill them in the "meta" frame
// NOTE: the packet itself is not modified by this lookup!
		if (findRouteEntry(route_tbl, gNtohl(tmpbuf, ip_pkt->ip_dst),
				pkt->frame.nxth_ip_addr, &(pkt->frame.dst_interface))
				== EXIT_FAILURE) {
			verbose(2,
					"[IPOutgoingPacket]:: findRouteEntry failed (newflag = 0)");
			return EXIT_FAILURE;
		}
	} else if (newflag == 1) {
// non REPLY PACKET -- this is a new packet; set all fields
		ip_pkt->ip_version = 4;
		ip_pkt->ip_hdr_len = 5;
		ip_pkt->ip_tos = 0;
		ip_pkt->ip_identifier = IP_OFFMASK & random();
		RESET_DF_BITS(ip_pkt->ip_frag_off);
		RESET_MF_BITS(ip_pkt->ip_frag_off);
		ip_pkt->ip_frag_off = 0;

		COPY_IP(ip_pkt->ip_dst, gHtonl(tmpbuf, dst_ip));
		ip_pkt->ip_pkt_len = htons(size + ip_pkt->ip_hdr_len * 4);

		verbose(2, "[IPOutgoingPacket]:: lookup next hop ");
// find the nexthop and interface and fill them in the "meta" frame
// NOTE: the packet itself is not modified by this lookup!
		if (ip_pkt->ip_dst[0] >= 224 && dst_ip[0] <= 239) {
			int forward_interface = IGMP_GetGroupInterfaces(pkt);
			if (forward_interface == -1) {
				verbose(1, "1 Yes interface for this ip address %d.%d.%d.%d",
						ip_pkt->ip_dst[0], ip_pkt->ip_dst[1], ip_pkt->ip_dst[2],
						ip_pkt->ip_dst[3]);
				return EXIT_FAILURE;
			}
			pkt->frame.dst_interface = forward_interface;
			verbose(1, "1 Yes interface for this ip address %d.%d.%d.%d",
					ip_pkt->ip_dst[0], ip_pkt->ip_dst[1], ip_pkt->ip_dst[2],
					ip_pkt->ip_dst[3]);
		} else {
			if (findRouteEntry(route_tbl, gNtohl(tmpbuf, ip_pkt->ip_dst),
					pkt->frame.nxth_ip_addr, &(pkt->frame.dst_interface))
					== EXIT_FAILURE) {
				verbose(1, " 0 NO  interface for this ip address %d.%d.%d.%d",
						ip_pkt->ip_dst[0], ip_pkt->ip_dst[1], ip_pkt->ip_dst[2],
						ip_pkt->ip_dst[3]);
				verbose(2,
						"[IPOutgoingPacket]:: findRouteEntry failed (newflag = 1)");
				return EXIT_FAILURE;
			}
			verbose(1, "0 WAS  interface for this ip address %d.%d.%d.%d",
					ip_pkt->ip_dst[0], ip_pkt->ip_dst[1], ip_pkt->ip_dst[2],
					ip_pkt->ip_dst[3]);
		}

		verbose(2, "[IPOutgoingPacket]:: lookup MTU of nexthop");
// lookup the IP address of the destination interface..
		if ((status = findInterfaceIP(MTU_tbl, pkt->frame.dst_interface,
				iface_ip_addr)) == EXIT_FAILURE)
			return EXIT_FAILURE;
// the outgoing packet should have the interface IP as source
		COPY_IP(ip_pkt->ip_src, gHtonl(tmpbuf, iface_ip_addr));
		verbose(2,
				"[IPOutgoingPacket]:: almost done processing the IP header.");
	} else {
		error(
				"[IPOutgoingPacket]:: unknown outgoing packet action.. packet discarded ");
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

/*int IGMPPreparePacket(gpacket_t *pkt, uchar *dst_ip, int size, int newflag, int src_prot) {
 ip_packet_t *ip_pkt = (ip_packet_t *)pkt->data.data;
 char tmpbuf[MAX_TMPBUF_LEN];
 uchar iface_ip_addr[4];
 int status;
 ip_pkt->ip_ttl = 1;                        // set TTL to default value
 ip_pkt->ip_cksum = 0;                       // reset the checksum field
 ip_pkt->ip_prot = IGMP_PROTOCOL;  // set the protocol field
 if (newflag == 0)
 {
 COPY_IP(ip_pkt->ip_dst, ip_pkt->ip_src); 		    // set dst to original src
 COPY_IP(ip_pkt->ip_src, gHtonl(tmpbuf, pkt->frame.src_ip_addr));    // set src to me

 // find the nexthop and interface and fill them in the "meta" frame
 // NOTE: the packet itself is not modified by this lookup!
 if (findRouteEntry(route_tbl, gNtohl(tmpbuf, ip_pkt->ip_dst),
 pkt->frame.nxth_ip_addr, &(pkt->frame.dst_interface)) == EXIT_FAILURE)
 {
 verbose(2,"[IPOutgoingPacket]:: findRouteEntry failed (newflag = 0)");
 return EXIT_FAILURE;
 }
 } else if (newflag == 1)
 {
 // non REPLY PACKET -- this is a new packet; set all fields
 ip_pkt->ip_version = 4;
 ip_pkt->ip_hdr_len = 5;
 ip_pkt->ip_tos = 0;
 ip_pkt->ip_identifier = IP_OFFMASK & random();
 RESET_DF_BITS(ip_pkt->ip_frag_off);
 RESET_MF_BITS(ip_pkt->ip_frag_off);
 ip_pkt->ip_frag_off = 0;

 COPY_IP(ip_pkt->ip_dst, gHtonl(tmpbuf, dst_ip));
 ip_pkt->ip_pkt_len = htons(size + ip_pkt->ip_hdr_len * 4);

 verbose(2, "[IPOutgoingPacket]:: lookup next hop ");
 // find the nexthop and interface and fill them in the "meta" frame
 // NOTE: the packet itself is not modified by this lookup!

 if (dst_ip[0] >= 224 && dst_ip[0] <= 239)
 {
 int forward_interface = IGMP_GetGroupInterfaces(pkt);
 pkt->frame.dst_interface = forward_interface;
 if (pkt->frame.dst_interface == -1)
 {
 verbose (1, "No interface for this ip address %d.%d.%d.%d", ip_pkt->ip_dst[0], ip_pkt->ip_dst[1], ip_pkt->ip_dst[2], ip_pkt->ip_dst[3]);
 return EXIT_FAILURE;
 }
 }
 else
 {
 if (findRouteEntry(route_tbl, gNtohl(tmpbuf, ip_pkt->ip_dst),
 pkt->frame.nxth_ip_addr, &(pkt->frame.dst_interface)) == EXIT_FAILURE)
 {
 verbose (1, "No interface for this ip address %d.%d.%d.%d", ip_pkt->ip_dst[0], ip_pkt->ip_dst[1], ip_pkt->ip_dst[2], ip_pkt->ip_dst[3]);
 return EXIT_FAILURE;
 }
 }

 verbose(2, "[IPOutgoingPacket]:: lookup MTU of nexthop");
 // lookup the IP address of the destination interface..
 if ((status = findInterfaceIP(MTU_tbl, pkt->frame.dst_interface,
 iface_ip_addr)) == EXIT_FAILURE)
 return EXIT_FAILURE;

 // the outgoing packet should have the interface IP as source
 COPY_IP(ip_pkt->ip_src, gHtonl(tmpbuf, iface_ip_addr));
 verbose(2, "[IPOutgoingPacket]:: almost done processing the IP header.");
 } else
 {
 error("[IPOutgoingPacket]:: unknown outgoing packet action.. packet discarded ");
 return EXIT_FAILURE;
 }
 return EXIT_SUCCESS;
 }
 */
int IPOutgoingPacketChecksumAndSend(gpacket_t *pkt, uchar *dst_ip, int size,
		int newflag, int src_prot) {
	ip_packet_t *ip_pkt = (ip_packet_t *) pkt->data.data;
	ushort cksum;
// compute the new checksum
	cksum = checksum((uchar *) ip_pkt, ip_pkt->ip_hdr_len * 2);
	ip_pkt->ip_cksum = htons(cksum);
	pkt->data.header.prot = htons(IP_PROTOCOL);
	IPSend2Output(pkt);
	verbose(2, "[IPOutgoingPacket]:: IP packet sent to output queue.. ");
	return EXIT_SUCCESS;
}

/*
 * this function processes the IP packets that are reinjected into the
 * IP layer by ICMP, UDP, and other higher-layers.
 * There can be two scenarios. The packet can be a reply for an original
 * query OR it can be a new one. The processing performed by this function depends
 * on the packet type..
 * IMPORTANT: src_prot is the source protocol number.
 */
int IPOutgoingPacket(gpacket_t *pkt, uchar *dst_ip, int size, int newflag,
		int src_prot) {
	int result = IPPreparePacket(pkt, dst_ip, size, newflag, src_prot);
	if (result != EXIT_SUCCESS) {
		return result;
	}
	return IPOutgoingPacketChecksumAndSend(pkt, dst_ip, size, newflag, src_prot);
}

int IGMPOutgoingPacket(gpacket_t *pkt, uchar *dst_ip, int size, int newflag,
		int src_prot) {
	verbose(1, "call IGMPPreparePacket");
	int result = IGMPPreparePacket(pkt, dst_ip, size, newflag, src_prot);
	if (result != EXIT_SUCCESS) {
		verbose(1, "IGMPPreparePacket failed");
		return result;
	}
	verbose(1, "call IPOutgoingPacketChecksumAndSend");
	return IPOutgoingPacketChecksumAndSend(pkt, dst_ip, size, newflag, src_prot);
}

/*
 * IPSend2Output - write to the output Queue..
 */
int IPSend2Output(gpacket_t *pkt) {
	int vlevel;
	verbose(1, "GUY TEST 2output  0");

	if (pkt == NULL) {
		verbose(1, "[IPSend2Output]:: NULL pointer error... nothing sent");
		return EXIT_FAILURE;
	}

	verbose(1, "GUY TEST 2output  1");
	vlevel = prog_verbosity_level();
	verbose(1, "GUY TEST 2output  2");
	if (vlevel >= 3)
		printGPacket(pkt, vlevel, "IP_ROUTINE");

	verbose(1, "GUY TEST 2output 3");
	return writeQueue(pcore->outputQ, (void *) pkt, sizeof(gpacket_t));
}

/*
 * check whether the IP packet has correct checksum and
 * version number... this router is hard coded for IP version 4!
 * NOTE: we don't send any ICMP error messages to the source - instead
 * we silently drop the packet. It seems (should check carefully) that
 * ICMP does not have a facility to report this kind of condition.
 * May be this condition is not likely to happen???
 */
int IPVerifyPacket(ip_packet_t *ip_pkt) {
	char tmpbuf[MAX_TMPBUF_LEN];
	int hdr_len = ip_pkt->ip_hdr_len;

// verify the header checksum
	if (checksum((void *) ip_pkt, hdr_len * 2) != 0) {
		verbose(2,
				"[IPVerifyPacket]:: packet from %s failed checksum, packet thrown",
				IP2Dot(tmpbuf, gNtohl((tmpbuf + 20), ip_pkt->ip_src)));
		return EXIT_FAILURE;
	}

// Check correct IP version
	if (ip_pkt->ip_version != 4) {
		verbose(2, "[IPVerifyPacket]:: from %s failed checksum, packet thrown",
				IP2Dot(tmpbuf, gNtohl((tmpbuf + 20), ip_pkt->ip_src)));
		return EXIT_FAILURE;
	}
	verbose(2, "[IPVerifyPacket]:: packet from %s passed checks.",
			IP2Dot(tmpbuf, gNtohl((tmpbuf + 20), ip_pkt->ip_src)));
	return EXIT_SUCCESS;
}

/*
 * Checks if two IP addresses are on the same network
 * returns: EXIT_FAILURE if not and EXIT_SUCCESS if they are
 */
int isInSameNetwork(uchar *ip_addr1, uchar *ip_addr2) {
	char tmpbuf[MAX_TMPBUF_LEN];
	int i, j;
	uchar net1[4], net2[4];

	for (i = 0; i < MAX_ROUTES; i++) {
		if (route_tbl[i].is_empty == TRUE)
			continue;
// TODO: Could there be a bug here? What about default routes with 0.0.0.0??
		for (j = 0; j < 4; j++) {
			net1[j] = ip_addr1[j] & route_tbl[i].netmask[j];
			net2[j] = ip_addr2[j] & route_tbl[i].netmask[j];
		}
		if (COMPARE_IP(net1, net2) == 0) {
			verbose(2,
					"[isInSameNetwork]:: IPs %s and %s are on the same network %s",
					IP2Dot(tmpbuf, ip_addr1), IP2Dot((tmpbuf + 20), ip_addr2),
					IP2Dot((tmpbuf + 40), route_tbl[i].network));

			return EXIT_SUCCESS;
		}
	}

	verbose(2, "[isInSameNetwork]:: IPs %s and %s are not on the same network",
			IP2Dot(tmpbuf, ip_addr1), IP2Dot((tmpbuf + 20), ip_addr2));

	return EXIT_FAILURE;
}

void IGMPFloodNeighbors(gpacket_t *in_pkt) {
	verbose(1, "GUY TEST: FLOOD NEIGHBOURS");
// send to all neighbours by trying all entries in the router.
	int interface = 0;
	while (interface < MAX_ROUTES) {
		if (route_tbl[interface].is_empty == 0) {

			gpacket_t *out_pkt = (gpacket_t *) malloc(sizeof(gpacket_t));
			memcpy(out_pkt, in_pkt, sizeof(*in_pkt));

			uchar temp_destination_ip[4];
			COPY_IP(temp_destination_ip, route_tbl[interface].nexthop);

			int success = IGMPOutgoingPacket(out_pkt, temp_destination_ip, 8, 1,
					IGMP_PROTOCOL);

		}
		interface++;
	}
}
