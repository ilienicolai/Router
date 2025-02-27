#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>

#define ETHERTYPE_IP 0x0800
#define ETHERTYPE_ARP 0x806
/* Routing table */
struct route_table_entry *rtable;
int rtable_len;

/* Arp table table */
struct arp_table_entry *arp_table;
int arp_table_len;
queue pack_que; // que for waiting packets

// struct to memorize pack in que
struct que_packet {
	size_t len;
	char *buf;
	struct route_table_entry *best_route;
};
int que_len = 0; // number of packs in que

struct route_table_entry *get_best_route(uint32_t ip_dest) {
	uint32_t max_mask = 0;
	struct route_table_entry *best_router = NULL;
	for (int i = 0; i < rtable_len; i++) {
		if (rtable[i].prefix == (ip_dest & rtable[i].mask) && rtable[i].mask >= max_mask) {
			best_router = &rtable[i];
			max_mask = rtable[i].mask;
		}
	}
	return best_router;
}

struct arp_table_entry *get_mac_entry(uint32_t given_ip) {
	for (int i = 0; i < arp_table_len; i++) {
		if (arp_table[i].ip == given_ip)
			return &arp_table[i];
	}
	return NULL;
}
int send_ICMP_ttl_dest(char *buf, uint8_t case_icmp, int interface) {
	struct ether_header *eth_hdr = (struct ether_header *) buf;
	struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));
	
	// ethernet header
	struct ether_header new_eth_hdr;
	memcpy(&(new_eth_hdr.ether_dhost), &(eth_hdr->ether_shost), 6);
	memcpy(&(new_eth_hdr.ether_shost), &(eth_hdr->ether_dhost), 6);
	new_eth_hdr.ether_type = htons(0x0800);

	// ip header
	struct iphdr new_ip_hdr;
	new_ip_hdr.saddr = htonl(inet_network(get_interface_ip(interface)));
	new_ip_hdr.daddr = ip_hdr->saddr;
	new_ip_hdr.ttl = 64;
	new_ip_hdr.frag_off = 0;
	new_ip_hdr.tos = 0;
	new_ip_hdr.version = 4;
	new_ip_hdr.ihl = 5;
	new_ip_hdr.protocol = 1;
	new_ip_hdr.tot_len = htons(2 * sizeof(struct iphdr) + sizeof(struct icmphdr) + 8);
	new_ip_hdr.check = 0;
	new_ip_hdr.check = htons(checksum((uint16_t *)(&new_ip_hdr), sizeof(struct iphdr)));

	//icmp header
	struct icmphdr icmp_hdr;
	icmp_hdr.type = case_icmp;
	icmp_hdr.code = 0;
	icmp_hdr.checksum = 0;
	icmp_hdr.checksum = htons(checksum((uint16_t *)(&icmp_hdr), sizeof(struct icmphdr)));

	// ICMP pack
	int eth_size = sizeof(struct ether_header);
	int ip_size = sizeof(struct iphdr);
	int icmp_size = sizeof(struct icmphdr);
	int total_size = eth_size + ip_size + icmp_size + 8;
	char *new_buff = malloc(total_size + ip_size);
	memcpy(new_buff, &new_eth_hdr, eth_size);
	memcpy(new_buff + eth_size, &new_ip_hdr, ip_size);
	memcpy(new_buff + eth_size + ip_size, &icmp_hdr, icmp_size);
	memcpy(new_buff + total_size - 8, buf + eth_size, ip_size + 8);
	send_to_link(interface, new_buff, total_size + ip_size);
	return 0;

}
int send_ARP_request(char * buf, size_t len, struct route_table_entry *best_route) {
	struct ether_header *eth_hdr = (struct ether_header *) buf;
	// ethernet header
	struct ether_header new_eth_hdr;
	memcpy(&new_eth_hdr, eth_hdr, sizeof(struct ether_header));
	new_eth_hdr.ether_type = htons(0x806);
	memset(new_eth_hdr.ether_dhost, 0xff, 6);
	get_interface_mac(best_route->interface, new_eth_hdr.ether_shost);

	// ARP header
	struct arp_header new_arp_hdr;
	new_arp_hdr.op = htons(1);
	new_arp_hdr.spa = htonl(inet_network(get_interface_ip(best_route->interface)));
	new_arp_hdr.tpa = best_route->next_hop;
	new_arp_hdr.hlen = 6;
	new_arp_hdr.plen = 4;
	new_arp_hdr.htype = htons(1);
	new_arp_hdr.ptype = htons(0x0800);
	get_interface_mac(best_route->interface, new_arp_hdr.sha);
	memset(new_arp_hdr.tha, 0xff, 6);

	// build ARP pack
	int arp_len = sizeof(struct ether_header) + sizeof(struct arp_header);
	char *arp_pack = malloc(arp_len);
	memcpy(arp_pack, (char *)(&new_eth_hdr), sizeof(struct ether_header));
	memcpy(arp_pack + sizeof(struct ether_header), (char *)(&new_arp_hdr), sizeof(struct arp_header));

	// build pack for que
	struct que_packet *pack_to_que = malloc(sizeof(struct que_packet));
	pack_to_que->buf = malloc(len);
	memcpy(pack_to_que->buf, buf, len);
	pack_to_que->len = len;
	pack_to_que->best_route = best_route; 
	queue_enq(pack_que, (void*)pack_to_que);
	que_len++;
	send_to_link(best_route->interface, arp_pack, arp_len);
	return 0;
}
int send_IPv4(char *buf, size_t len, int interface) {
	struct ether_header *eth_hdr = (struct ether_header *) buf;
	struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));
	// verify checksum
	uint16_t oldch = ip_hdr->check;
	ip_hdr->check = 0;
	uint16_t newch = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));
	if (newch != oldch) {
		return -1;
	}
	// identify best route
	struct route_table_entry *dest_entry = get_best_route(ip_hdr->daddr);
	if (!dest_entry) { 
		send_ICMP_ttl_dest(buf, (uint8_t)3, interface);
		return 1;
	}
	// check ttl
	if (ip_hdr->ttl <= 1) {
		send_ICMP_ttl_dest(buf, (uint8_t)11, interface);
		return 3;
	}
	ip_hdr->ttl--;
	ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));
	// search mac address of next hop
	struct arp_table_entry *dest_mac = get_mac_entry(dest_entry->next_hop);
	if (!dest_mac) { 	// mac address not found => generate arp request
		send_ARP_request(buf, len, dest_entry);
		return 2;
	}
	// send pack
	memcpy(eth_hdr->ether_dhost, dest_mac->mac, 6);
	get_interface_mac(dest_entry->interface, eth_hdr->ether_shost);
	send_to_link(dest_entry->interface, buf, len);
	return 0;	
}

int send_ICMP_echo_reply(char *buf, size_t len, int interface) {
	struct ether_header *eth_hdr = (struct ether_header *) buf;
	struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));

	// verify checksum
	uint16_t oldch = ip_hdr->check;
	ip_hdr->check = 0;
	uint16_t newch = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));
	if (newch != oldch) {
		return 2;
	}
	//check ttl
	if (ip_hdr->ttl <= 1) {
		send_ICMP_ttl_dest(buf, 11, interface);
		return 1;
	}
	// switch ip addr
	uint32_t aux = ip_hdr->daddr;
	ip_hdr->daddr = ip_hdr->saddr;
	ip_hdr->saddr = aux;
	uint8_t aux_mac[6];
	ip_hdr->check = 0;

	// update checksum
	ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct icmphdr)));
	// switch mac
	memcpy(aux_mac, eth_hdr->ether_dhost, 6);
	memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, 6);
	memcpy(eth_hdr->ether_shost, aux_mac, 6);

	// update icmp
	struct icmphdr *icmp_hdr = (struct icmphdr *)(buf + sizeof(struct ether_header) + sizeof(struct iphdr));
	icmp_hdr->type = 0;
	icmp_hdr->checksum = 0;
	icmp_hdr->checksum = htons(checksum((uint16_t *)icmp_hdr, sizeof(struct icmphdr)));
	send_to_link(interface, buf, len);
	return 0;
}

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];
	pack_que = queue_create();

	// Do not modify this line
	init(argc - 2, argv + 2);
	/* Code to allocate the MAC and route tables */
	rtable = malloc(sizeof(struct route_table_entry) * 100000);
	/* DIE is a macro for sanity checks */
	DIE(rtable == NULL, "memory");

	arp_table = malloc(sizeof(struct  arp_table_entry) * 100000);
	DIE(arp_table == NULL, "memory");
	
	/* Read the static routing table and the MAC table */
	rtable_len = read_rtable(argv[1], rtable);

	int num_pack = 0;
	while (1) {

		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		
		DIE(interface < 0, "recv_from_any_links");
		struct ether_header *eth_hdr = (struct ether_header *) buf;
		if (ntohs(eth_hdr->ether_type) == ETHERTYPE_IP) {
			num_pack++;
			struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));
			// check if pack is for the router
			if (htonl(inet_network(get_interface_ip(interface))) == ip_hdr->daddr) {
				send_ICMP_echo_reply(buf, len, interface);
			} else {
				send_IPv4(buf, len, interface);
			}
			continue;
		}

		// ARP protocol
		struct arp_header *arp_hdr = (struct arp_header *)(buf + sizeof(struct ether_header));
		if (ntohs(arp_hdr->op) == 1) { // received arp request
			//update ethernet header
			memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, 6);
			get_interface_mac(interface,eth_hdr->ether_shost);

			//update arp mac
			memcpy(arp_hdr->tha, arp_hdr->sha, 6);
			get_interface_mac(interface, arp_hdr->sha);

			//update arp ip
			u_int32_t aux = arp_hdr->spa;
			arp_hdr->spa = arp_hdr->tpa;
			arp_hdr->tpa = aux;
			arp_hdr->op = htons(2);
			send_to_link(interface, buf, len);
		} else {
			if (ntohs(arp_hdr->op) == 2 && que_len != 0) { //received arp reply
				//update arp table
				arp_table[arp_table_len].ip = arp_hdr->spa;
				memcpy(arp_table[arp_table_len].mac, arp_hdr->sha, 6);
				arp_table_len++;
				int count = 0; //number of packs send from que

				for (int i = 0; i<que_len; i++) {
					// extract pack from que
					struct que_packet *pack = (struct que_packet*)(queue_deq(pack_que));
					// find mac
					struct arp_table_entry *dest_mac = get_mac_entry(pack->best_route->next_hop);
					if (!dest_mac){
						// we do not find a match for this pack so we reput it in que
						queue_enq(pack_que, pack);
					} else {
						// mac match found
						count++;
						// update ethernet header and sent
						struct ether_header *pack_eth_hdr = (struct ether_header *)(pack->buf);
						memcpy(pack_eth_hdr->ether_dhost, dest_mac->mac, 6);
						get_interface_mac(pack->best_route->interface, eth_hdr->ether_shost);
						send_to_link(pack->best_route->interface, pack->buf, pack->len);
					}
				}
				que_len = que_len - count;
			}
		}
	}
	free(rtable);
}

