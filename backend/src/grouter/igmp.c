#include "igmp.h"
#include "protocols.h"
#include <sys/time.h>
#include <signal.h>
#define TIMER_INTERVAL 1
// state information on outstanding ping..
//pingstat_t pstat;
struct itimerval timer;
/*
void time_out(void) {
	//time_t time_now;
	//time(&time_now);
  	//verbose(1, "Times up betch: %s\n", ctime(&time_now));

  	verbose(1, "Sending query");
  	gpacket_t *out_pkt = (gpacket_t *) malloc(sizeof(gpacket_t));
	ip_packet_t *ipkt = (ip_packet_t *)(out_pkt->data.data);
	ipkt->ip_hdr_len = 5;
	igmphdr_t *igmphdr = (igmphdr_t *)((uchar *)ipkt + ipkt->ip_hdr_len*4);

	out_pkt->frame.dst_interface = 1;
	uchar group_dest[4];
	group_dest[0] = 224; group_dest[1] = 0; group_dest[2] = 0; group_dest[3] = 1;
	COPY_IP( out_pkt->data.header.dst, group_dest);

	ushort cksum;
	igmphdr->type = IGMP_HOST_MEMBERSHIP_QUERY;
	igmphdr->code = 0;
	igmphdr->group = 0;
	igmphdr->checksum = 0;
	cksum = checksum((uchar *)igmphdr, ipkt->ip_hdr_len/2);
	igmphdr->checksum = htons(cksum);

	if (IPSend2Output(out_pkt) != EXIT_SUCCESS)
	{
		verbose(1, "sendingproblems");
	}
	else
	{
		verbose(1, "Sent success!!");
	}
//	check_group_resposes();
}

void set_timer(int interval)
{
  if (signal(SIGALRM, (void (*)(int)) time_out) == SIG_ERR) {
    verbose(1, "SIGALRMproblems");
  }
  timer.it_value.tv_sec =     interval;
  timer.it_value.tv_usec =   0;
  timer.it_interval = timer.it_value;
  verbose(1, interval == 0 ? "Timer off" : "Starting timer: %d seconds", interval);
  if (setitimer(ITIMER_REAL, &timer, NULL) == -1) {
    verbose(1, "setitimerproblems");
  }
}

void check_group_resposes()
{
	if (group_list != NULL)
	{
		while (list_has_next(group_list)) {
			igmp_group_list_item *current_group = (igmp_group_list_item *) list_next(group_list);

			//check if timed oput and decrement time left
			if (current_group->time_left_to_respond-- < 1)
			{
				//remove group
				verbose(1, "removing group");
				//list_remove_current(group_list);
			}
		}
		if (list_empty(group_list))
		{
			verbose(1, "List empty");
			//set_timer(0);
		}
	}
}
*/
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
//		set_timer(TIMER_INTERVAL);
		IGMPProcessMembershipReport(in_pkt);
		break;

	case IGMP_DVMRP_MESSAGE:
		switch (igmphdr->code) {
			case IGMP_DVMRP_PROBE:

				break;
			case IGMP_DVMRP_REPORT:

				break;
			case IGMP_DVMRP_PRUNE:

				break;
			case IGMP_DVMRP_GRAFT:
				IGMPProcessGraft(in_pkt);
				break;
		}
		verbose(2,
				"[IGMPProcessPacket]:: IGMP processing DVMRP Message");
		break;
	}
}

void IGMPSendGraft(uchar new_group[4]) {

  	verbose(1, "Sending query");
  	gpacket_t *out_pkt = (gpacket_t *) malloc(sizeof(gpacket_t));
	ip_packet_t *ipkt = (ip_packet_t *)(out_pkt->data.data);
	ipkt->ip_hdr_len = 5;
	igmphdr_t *igmphdr = (igmphdr_t *)((uchar *)ipkt + ipkt->ip_hdr_len*4);

	out_pkt->frame.dst_interface = 1;

	uchar src_dest[4];
	src_dest[0] = 192; src_dest[1] = 168; src_dest[2] = 1; src_dest[3] = 128;
	COPY_IP(ipkt->ip_src, src_dest);
	ipkt->ip_ttl = 1;
	ipkt->ip_prot = IGMP_PROTOCOL;	  // set the protocol field

	uchar group_dest[4];
	//	group_dest[0] = 224; group_dest[1] = 0; group_dest[2] = 0; group_dest[3] = 2;
	group_dest[0] = 224; group_dest[1] = 0; group_dest[2] = 0; group_dest[3] = 1;
//	group_dest[0] = 192; group_dest[1] = 168; group_dest[2] = 1; group_dest[3] = 2;
	COPY_IP(out_pkt->data.header.dst, group_dest);

	ushort cksum;
//	igmphdr->type = IGMP_DVMRP_GRAFT;
	igmphdr->type = IGMP_HOST_MEMBERSHIP_QUERY;
	igmphdr->code = 0;

	group_dest[0] = 0; group_dest[1] = 0; group_dest[2] = 0; group_dest[3] = 0;
	COPY_IP( igmphdr->group , new_group);

	igmphdr->checksum = 0;
	cksum = checksum((uchar *)igmphdr, ipkt->ip_hdr_len/2);
	igmphdr->checksum = htons(cksum);

	out_pkt->frame.dst_interface = 1;

	if (IPSend2Output(out_pkt) != EXIT_SUCCESS)
	{
		verbose(1, "[IGMPSendGraft]sending failed");
	}
	else
	{
		verbose(1, "Sent success!!");
	}
}

void IGMPProcessGraft(gpacket_t *in_pkt) {
	ip_packet_t *ipkt = (ip_packet_t *) in_pkt->data.data;
	int iphdrlen = ipkt->ip_hdr_len * 4;
	igmphdr_t *igmphdr = (igmphdr_t *) ((uchar *) ipkt + iphdrlen);
	uchar *igmppkt_b = (uchar *) igmphdr;

	if (dvmrp_pair_table == NULL)
	{
		dvmrp_pair_table = list_create(NULL);
	}

	// Go through all the groups, and try to find the packet's group.
	int found_group_in_table = 0;							// 1 if found a group, 0 if we didn't find one
	while (list_has_next(dvmrp_pair_table)) {
		dvmrp_pair_table_item *nextItem = (dvmrp_pair_table_item *) list_next(dvmrp_pair_table);

		// If the packet matches the group.
		// Have Group?
		if (COMPARE_IP(nextItem->multicastIP, ipkt->ip_dst) == 0) {
			found_group_in_table = 1;
		}
	}

	if (found_group_in_table == 0)
	{
		dvmrp_pair_table_item *newTableEntry = (dvmrp_pair_table_item *) malloc(sizeof(dvmrp_pair_table_item));
		//COPY_IP(newGroup->, in_pkt->data.header.dst);
		//newGroup->interface = in_pkt->frame.src_interface;
		//list_append(group_list, newGroup);
	}

}

int IGMP_GetGroupInterfaces(gpacket_t *in_pkt) {
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
			if (COMPARE_MAC(nextItem->groupMAC, in_pkt->data.header.dst) == 0) {
				return nextItem->interface;
			}
		}
	}

	return -1;
}

/*List * IGMP_GetGroupIPs(gpacket_t *in_pkt) {
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
*/
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
		if (COMPARE_MAC(nextItem->groupMAC, in_pkt->data.header.dst) == 0) {
			found_group = 1;
			//reset time to respond
			verbose(1, "Resettig respomse time");
			nextItem->time_left_to_respond = 3;
		}
	}

	if (found_group == 0)
	{
		igmp_group_list_item *newGroup = (igmp_group_list_item *) malloc(sizeof(igmp_group_list_item));
		COPY_MAC( newGroup->groupMAC, in_pkt->data.header.dst);
		IGMPSendGraft(in_pkt->data.header.dst);

		newGroup->interface = in_pkt->frame.src_interface;
		newGroup->time_left_to_respond = 3;
		list_append(group_list, newGroup);
	}
}

