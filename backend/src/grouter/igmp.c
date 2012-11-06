#include "igmp.h"

// state information on outstanding ping..
//pingstat_t pstat;

void IGMP_RCV(gpacket_t *in_pkt) {
	verbose(1, "GUY TEST: 0.0");

	ip_packet_t *ip_pkt = (ip_packet_t *) in_pkt->data.data;
	int iphdrlen = ip_pkt->ip_hdr_len * 4;
	igmphdr_t *igmphdr = (igmphdr_t *) ((uchar *) ip_pkt + iphdrlen);

	verbose(1, "GUY TEST: igmpType %d" , igmphdr->type);

	switch (igmphdr->type) {
	case IGMP_HOST_MEMBERSHIP_QUERY:
		verbose(1, "GUY TEST: 0.1");
		verbose(2,
				"[IGMPProcessPacket]:: IGMP processing for membership query request");
		//IGMPProcessMembershipQuery(in_pkt);
		break;

	case IGMP_HOST_MEMBERSHIP_REPORT:
		verbose(1, "GUY TEST: 0.2");
		verbose(2,
				"[IGMPProcessPacket]:: IGMP processing for membership report request");
		IGMPProcessMembershipReport(in_pkt);
		break;
	}
}
void IPCompareToIGMP(gpacket_t *in_pkt) {

}

void IGMPProcessMembershipReport(gpacket_t *in_pkt) {
	verbose(1, "GUY TEST: 1.0");
	ip_packet_t *ipkt = (ip_packet_t *) in_pkt->data.data;
	int iphdrlen = ipkt->ip_hdr_len * 4;
	igmphdr_t *igmphdr = (igmphdr_t *) ((uchar *) ipkt + iphdrlen);
	uchar *igmppkt_b = (uchar *) igmphdr;

	verbose(2, "[IGMPProcessMembershipReport]::, %d", in_pkt->data.data);

	verbose(1, "GUY TEST: 1.0");

	//Create a group list on the first run.
	if (group_list == NULL)
	{
		verbose(1, "GUY TEST: 1.1: create group list");
		group_list = list_create(NULL);
	}

	// Go through all the groups, and try to find the packet's group.
	int found_group = 0;							// 1 if found a group, 0 if we didn't find one
	while (list_has_next(group_list)) {
		verbose(1, "GUY TEST: 1.2: list has next iterate");

		igmp_group_list_item *nextItem = (igmp_group_list_item *) list_next(group_list);

		// If the packet matches the group.
		verbose(1, "GUY TEST: 1.2.0: attempt to match: %d %d %d %d," );

		// Have Group?
		if (COMPARE_MAC(nextItem->groupID, in_pkt->data.header.dst) == 0) {
			verbose(1, "GUY TEST: 1.2.1: group match");
			found_group = 1;
			// TODO: add the new IP to the group's list.

			// make sure the hosts list exist
			if (nextItem->hosts == NULL)
			{
				verbose(1, "GUY TEST: 1.2.2  new host list was created, which shouldnt happen");
				nextItem->hosts = list_create(NULL);
			}

			// Do we have the packet.
			int found_packet = 0;
			while (list_has_next(nextItem->hosts)) {
				verbose(1, "GUY TEST: 1.2.3 iterating over the host list");
				gpacket_t *nextHostItem = (gpacket_t *) list_next(nextItem->hosts);
				// If the MAC source matches, we have the same host.
				if (COMPARE_MAC(nextHostItem->data.header.src, in_pkt->data.header.src) == 0) {
					verbose(1, "GUY TEST: 1.2.4 the src matches the saved source MAC");
					found_packet = 1;
				}
			}
			// IF packet not in the group's host list yet
			if (found_packet == 0)
			{
				list_append(nextItem->hosts, in_pkt);
				verbose(1, "GUY TEST: 1.2.5: we did NOT find a match");
				verbose(1, "GUY TEST: 1.2.6 appended the new host");
			}

			verbose(1, "GUY TEST: 1.2.7 host size is now %d" , list_length(nextItem->hosts));

		}
	}

	if (found_group == 0)
	{
		verbose(1, "GUY TEST: 1.3 group not found");
		// TODO: create a list, add the packet, and add it to the group.
		// make sure the hosts list exist

		igmp_group_list_item *newGroup = (igmp_group_list_item *) malloc(sizeof(igmp_group_list_item));

		COPY_MAC( newGroup->groupID, in_pkt->data.header.dst);
		newGroup->hosts = list_create(NULL);

		list_append(newGroup->hosts, in_pkt);
		verbose(1, "GUY TEST: 1.4.1 host size is now %d" , list_length(newGroup->hosts));

		list_append(group_list, newGroup);
		verbose(1, "GUY TEST: 1.4 new group created");
	}
	verbose(1, "GUY TEST: 1.5 list size is now %d" , list_length(group_list));


	// TODO : if no matches, then create a new group, add it to the list, and add the IP to the group's list.
}

/*	if (list_empty(group_list)) {
		verbose(1, "GUY TEST: 1.1 append");
		// TODO:
		list_append(group_list, in_pkt);
	} else {
		verbose(1, "GUY TEST: 1.2");
		while (list_has_next(group_list)) {
			ip_packet_t *nextItem = (ip_packet_t *) list_next(group_list);
			verbose(1, "GUY TEST: 1.3");

			if (nextItem->ip_dst == in_pkt->data.header.dst) {
				// TODO: we found an existing group in the list. We now add the new IP to the group's list.
				verbose(1, "GUY TEST: 1.4");
			}
		}
		// TODO : if no matches, then create a new group, add it to the list, and add the IP to the group's list.
	}
	*/

// Andrey comment: We are implementing the IGMPv1 protocol as there will be no leave messages to deal with.

/*
 void IGMPProcessTTLExpired(gpacket_t *in_pkt)
 {
 ip_packet_t *ipkt = (ip_packet_t *)in_pkt->data.data;
 int iphdrlen = ipkt->ip_hdr_len * 4;
 igmphdr_t *igmphdr = (igmphdr_t *)((uchar *)ipkt + iphdrlen);
 ushort cksum;
 char tmpbuf[MAX_TMPBUF_LEN];
 int iprevlen = iphdrlen + 8;  // IP header + 64 bits
 uchar prevbytes[MAX_IPREVLENGTH_IGMP];

 memcpy(prevbytes, (uchar *)ipkt, iprevlen);

 //form an IGMP TTL expired message and fill in IGMP header

 igmphdr->type = IGMP_TTL_EXPIRED;
 igmphdr->code = 0;
 igmphdr->checksum = 0;
 bzero((void *)&(igmphdr->un), sizeof(igmphdr->un));
 memcpy(((uchar *)igmphdr + 8), prevbytes, iprevlen);    //ip header + 64 bits of original pkt
 cksum = checksum((uchar *)igmphdr, (8 + iprevlen)/2 );
 igmphdr->checksum = htons(cksum);

 verbose(2, "[IGMPProcessTTLExpired]:: Sending... IGMP TTL expired message ");
 printf("Checksum at IGMP routine (TTL expired):  %x\n", cksum);

 // send the message back to the IP module for further processing ..
 // set the messsage as REPLY_PACKET
 IPOutgoingPacket(in_pkt, gNtohl(tmpbuf, ipkt->ip_src), 8+iprevlen, 1, IGMP_PROTOCOL);
 }

 // The router requests to see who is in the group
 void IGMPProcessMembershipQuery(gpacket_t *in_pkt)
 {
 ip_packet_t *ipkt = (ip_packet_t *)in_pkt->data.data;
 int iphdrlen = ipkt->ip_hdr_len * 4;
 igmphdr_t *igmphdr = (igmphdr_t *)((uchar *)ipkt + iphdrlen);
 uchar *icmppkt_b = (uchar *)igmphdr;

 ushort cksum;
 int ilen = ntohs(ipkt->ip_pkt_len) - iphdrlen;

 igmphdr->type = IGMP_HOST_MEMBERSHIP_QUERY;
 igmphdr->checksum = 0;
 if (IS_ODD(ilen))
 {
 // pad with a zero byte.. IP packet length remains the same
 icmppkt_b[ilen] = 0x0;
 ilen++;
 }
 cksum = checksum(igmppkt_b, (ilen / 2));
 igmphdr->checksum = htons(cksum);

 // send the message back to the IP routine for further processing ..
 // set the messsage as REPLY_PACKET..
 // destination IP and size need not be set. they can be obtained from the original packet
 IPOutgoingPacket(in_pkt, NULL, 0, 0, IGMP_PROTOCOL);
 }
 */
// Report == Client Response
//function to receive the datagram with IP multicast "1110"
//function to check the TTL, compare it with the router threshold value; if acceptabe increment the TTL and call forwarding function
