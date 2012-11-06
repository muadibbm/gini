#include "igmp.h"

// state information on outstanding ping..
//pingstat_t pstat;

void IGMP_RCV(gpacket_t *in_pkt) {

	ip_packet_t *ip_pkt = (ip_packet_t *) in_pkt->data.data;
	int iphdrlen = ip_pkt->ip_hdr_len * 4;
	igmphdr_t *igmphdr = (igmphdr_t *) ((uchar *) ip_pkt + iphdrlen);

	switch (igmphdr->type) {
	case IGMP_HOST_MEMBERSHIP_QUERY:
		verbose(2,
				"[IGMPProcessPacket]:: IGMP processing for membership query request");
		//IGMPProcessMembershipQuery(in_pkt);
		break;

	case IGMP_HOST_MEMBERSHIP_REPORT:
		verbose(2,
				"[IGMPProcessPacket]:: IGMP processing for membership report request");
		IGMPProcessMembershipReport(in_pkt);
		break;
	}
}

List * IGMP_GetGroupIPs(gpacket_t *in_pkt) {
	ip_packet_t *ipkt = (ip_packet_t *) in_pkt->data.data;
	int iphdrlen = ipkt->ip_hdr_len * 4;
	igmphdr_t *igmphdr = (igmphdr_t *) ((uchar *) ipkt + iphdrlen);
	uchar *igmppkt_b = (uchar *) igmphdr;



	//Create a group list on the first run.
	if (group_list != NULL)
	{
		while (list_has_next(group_list)) {
			igmp_group_list_item *nextItem = (igmp_group_list_item *) list_next(group_list);

			// If the packet matches the group copy the list
			if (COMPARE_MAC(nextItem->groupID, in_pkt->data.header.dst) == 0) {
				return nextItem->hosts;
			}
		}
	}

	return NULL;
}

void IGMPProcessMembershipReport(gpacket_t *in_pkt) {
	ip_packet_t *ipkt = (ip_packet_t *) in_pkt->data.data;
	int iphdrlen = ipkt->ip_hdr_len * 4;
	igmphdr_t *igmphdr = (igmphdr_t *) ((uchar *) ipkt + iphdrlen);
	uchar *igmppkt_b = (uchar *) igmphdr;

	verbose(2, "[IGMPProcessMembershipReport]::, %d", in_pkt->data.data);

	//Create a group list on the first run.
	if (group_list == NULL)
	{
		group_list = list_create(NULL);
	}

	// Go through all the groups, and try to find the packet's group.
	int found_group = 0;							// 1 if found a group, 0 if we didn't find one
	while (list_has_next(group_list)) {
		igmp_group_list_item *nextItem = (igmp_group_list_item *) list_next(group_list);

		// If the packet matches the group.
		// Have Group?
		if (COMPARE_MAC(nextItem->groupID, in_pkt->data.header.dst) == 0) {
			found_group = 1;
			// TODO: add the new IP to the group's list.

			// make sure the hosts list exist
			if (nextItem->hosts == NULL)
			{
				nextItem->hosts = list_create(NULL);
			}

			// Do we have the packet.
			int found_packet = 0;
			while (list_has_next(nextItem->hosts)) {
				gpacket_t *nextHostItem = (gpacket_t *) list_next(nextItem->hosts);
				// If the MAC source matches, we have the same host.
				if (COMPARE_MAC(nextHostItem->data.header.src, in_pkt->data.header.src) == 0) {
					found_packet = 1;
				}
			}
			// IF packet not in the group's host list yet
			if (found_packet == 0)
			{
				list_append(nextItem->hosts, in_pkt);
			}
		}
	}

	if (found_group == 0)
	{
		// TODO: create a list, add the packet, and add it to the group.
		// make sure the hosts list exist

		igmp_group_list_item *newGroup = (igmp_group_list_item *) malloc(sizeof(igmp_group_list_item));

		COPY_MAC( newGroup->groupID, in_pkt->data.header.dst);
		newGroup->hosts = list_create(NULL);

		list_append(newGroup->hosts, in_pkt);

		list_append(group_list, newGroup);
	}
}

