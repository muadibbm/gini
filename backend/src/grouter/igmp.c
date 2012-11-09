#include "igmp.h"
#include "protocols.h"
#include <sys/time.h>
#include <signal.h>
#define TIMER_INTERVAL 5
// state information on outstanding ping..
//pingstat_t pstat;
struct itimerval timer;

void time_out(void) {
}

void set_timer(int interval) {
	if (signal(SIGALRM, (void (*)(int)) time_out) == SIG_ERR) {
		verbose(1, "SIGALRMproblems");
	}
	timer.it_value.tv_sec = interval;
	timer.it_value.tv_usec = 0;
	timer.it_interval = timer.it_value;
	verbose(1, interval == 0 ? "Timer off" : "Starting timer: %d seconds",
			interval);
	if (setitimer(ITIMER_REAL, &timer, NULL) == -1) {
		verbose(1, "setitimerproblems");
	}
}

void check_group_resposes() {
	if (group_list != NULL) {
		while (list_has_next(group_list)) {
			igmp_group_list_item *current_group =
					(igmp_group_list_item *) list_next(group_list);

			//check if timed oput and decrement time left
			if (current_group->time_left_to_respond-- < 1) {
				//remove group
				verbose(1, "removing group");
				//list_remove_current(group_list);
			}
		}
		if (list_empty(group_list)) {
			verbose(1, "List empty");
			set_timer(0);
		}
	}
}

void IGMP_RCV(gpacket_t *in_pkt) {

	verbose(1, "GUY TEST: GOT IGMP PACKET");

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

		set_timer(TIMER_INTERVAL);
		IGMPProcessMembershipReport(in_pkt);
		break;
	case IGMP_DVMRP_PROBE:
		break;
	case IGMP_DVMRP_REPORT:
		break;
	case IGMP_DVMRP_PRUNE:
		break;
	case IGMP_DVMRP_GRAFT:
		verbose(1, "GUY TEST: GRAFT RECIEVED");
		IGMPProcessAndForwardGraft(in_pkt);
		break;
		verbose(2, "[IGMPProcessPacket]:: IGMP processing DVMRP Message");
		break;
	}
}

// Happens the first time you create a graft message. this message will be forwarded by other routers.
void IGMPCreateGraft(uchar new_group[4]) {
	verbose(1, "GUY TEST: create Graft of: %d %d %d %d ", new_group[0],
			new_group[1], new_group[2], new_group[3]);

//check if timed out and decrement time left
	gpacket_t *out_pkt = (gpacket_t *) malloc(sizeof(gpacket_t));
	ip_packet_t *ipkt = (ip_packet_t *) (out_pkt->data.data);
	ipkt->ip_hdr_len = 5;

// Setup IGMP packet headers
	igmphdr_t *igmphdr = (igmphdr_t *) ((uchar *) ipkt + ipkt->ip_hdr_len * 4);
	igmphdr->type = IGMP_DVMRP_GRAFT;
	igmphdr->unused = ipkt->ip_src[2];

	COPY_IP( igmphdr->group, new_group);

	ushort cksum;
	igmphdr->checksum = 0;
	cksum = checksum((uchar *) igmphdr, 8 / 2);
	igmphdr->checksum = htons(cksum);

	IGMPProcessAndForwardGraft(out_pkt);
}

// Get a graft, if we already have the group, stop. otherwise add it to the group list and forward the packet upward (but not where we came from).
void IGMPProcessAndForwardGraft(gpacket_t *in_pkt) {
	ip_packet_t *ipkt = (ip_packet_t *) in_pkt->data.data;

	int iphdrlen = ipkt->ip_hdr_len * 4;
	igmphdr_t *igmphdr = (igmphdr_t *) ((uchar *) ipkt + iphdrlen);
	uchar *igmppkt_b = (uchar *) igmphdr;

// make sure table exists
	if (dvmrp_pair_table == NULL) {
		dvmrp_pair_table = list_create(NULL);
	}

// Go through all the groups, and try to find the packet's group.
	int found_group_in_table = 0; // 1 if found a group, 0 if we didn't find one
	while (list_has_next(dvmrp_pair_table)) {
		dvmrp_pair_table_item *nextItem = (dvmrp_pair_table_item *) list_next(
				dvmrp_pair_table);

		// If the packet matches the group.
		// Have Group?
		if (COMPARE_IP(nextItem->multicastIP, ipkt->ip_dst) == 0) {
			// We use Ununsed to store the subnet (since 192.168.x.0 we have three constant values)
			if (nextItem->source_subnet == igmphdr->unused) {
				verbose(1, "GUY TEST: GRAFT TABLE FOUND");
				found_group_in_table = 1;
			}
		}
	}

	if (found_group_in_table == 0) {
		verbose(1, "GUY TEST: GRAFT TABLE ADDING");
		dvmrp_pair_table_item *newTableEntry = (dvmrp_pair_table_item *) malloc(
				sizeof(dvmrp_pair_table_item));
		COPY_IP(newTableEntry->multicastIP, ipkt->ip_dst);

		//get the subnet
		newTableEntry->source_subnet = igmphdr->unused;

		list_append(dvmrp_pair_table, newTableEntry);

		IGMPFloodNeighbors(in_pkt);
	}

}

int IGMP_GetGroupInterfaces(gpacket_t *in_pkt) {
	ip_packet_t *ipkt = (ip_packet_t *) in_pkt->data.data;
	int iphdrlen = ipkt->ip_hdr_len * 4;
	igmphdr_t *igmphdr = (igmphdr_t *) ((uchar *) ipkt + iphdrlen);
	uchar *igmppkt_b = (uchar *) igmphdr;

//Create a group list on the first run.
	if (group_list != NULL) {
		while (list_has_next(group_list)) {
			igmp_group_list_item *nextItem = (igmp_group_list_item *) list_next(
					group_list);

			// If the packet matches the group copy the list
			if (COMPARE_IP(nextItem->groupIP, ipkt->ip_dst) == 0) {
				return nextItem->interface;
			}
		}
	}

	return -1;
}

List * IGMP_GetGroupList() {
	return group_list;
}

void IGMPProcessMembershipReport(gpacket_t *in_pkt) {
	ip_packet_t *ipkt = (ip_packet_t *) in_pkt->data.data;
	int iphdrlen = ipkt->ip_hdr_len * 4;
	igmphdr_t *igmphdr = (igmphdr_t *) ((uchar *) ipkt + iphdrlen);
	uchar *igmppkt_b = (uchar *) igmphdr;

	verbose(2, "[IGMPProcessMembershipReport]::, %d", in_pkt->data.data);

//Create a group list on the first run.
	if (group_list == NULL) {
		group_list = list_create(NULL);
	}

// Go through all the groups, and try to find the packet's group.
	int found_group = 0;		// 1 if found a group, 0 if we didn't find one
	while (list_has_next(group_list)) {
		igmp_group_list_item *nextItem = (igmp_group_list_item *) list_next(
				group_list);

		// If the packet matches the group.
		// Have Group?
		if (COMPARE_IP(nextItem->groupIP, ipkt->ip_dst) == 0) {
			found_group = 1;
			//reset time to respond
			verbose(1, "Resettig respomse time");
			nextItem->time_left_to_respond = 3;
		}
	}

	if (found_group == 0) {
		igmp_group_list_item *newGroup = (igmp_group_list_item *) malloc(
				sizeof(igmp_group_list_item));
		COPY_IP(newGroup->groupIP, ipkt->ip_dst);

		newGroup->interface = in_pkt->frame.src_interface;
		newGroup->time_left_to_respond = 3;
		list_append(group_list, newGroup);
		verbose(1, "GUY TEST: added new group to the list: %d %d %d %d ",
				newGroup->groupIP[0], newGroup->groupIP[1],
				newGroup->groupIP[2], newGroup->groupIP[3]);

		IGMPCreateGraft(ipkt->ip_dst);
	}

}

List * IGMPGetGroupSubnets(gpacket_t *in_pkt) {

	List * outlist = list_create(NULL);

	ip_packet_t *ipkt = (ip_packet_t *) in_pkt->data.data;

	int iphdrlen = ipkt->ip_hdr_len * 4;
	igmphdr_t *igmphdr = (igmphdr_t *) ((uchar *) ipkt + iphdrlen);
	uchar *igmppkt_b = (uchar *) igmphdr;

	// make sure table exists
	if (dvmrp_pair_table != NULL) {
		// Go through all the groups, and try to find the packet's group.
		int found_group_in_table = 0;// 1 if found a group, 0 if we didn't find one
		while (list_has_next(dvmrp_pair_table)) {
			dvmrp_pair_table_item *nextItem =
					(dvmrp_pair_table_item *) list_next(dvmrp_pair_table);

			// If the packet matches the group.
			// Have Group?
			if (COMPARE_IP(nextItem->multicastIP, ipkt->ip_dst) == 0) {
				verbose(1, "GUY TEST: Found a group to forward to");
				found_group_in_table = 1;
				list_append_int(outlist, nextItem->source_subnet);

			}
		}
	}



	return outlist;
}

