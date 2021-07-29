#include <queue.h>
#include "skel.h"
#include "list.h"

// Basic tree structure used to store the entries of the routing table
typedef struct tree {
    struct tree *left;
    struct tree *right;
    list route_table_entries;
} tree_node;

// Function to dinamically alocate a node for the tree
tree_node *new_node() {
	tree_node *nod_nou = malloc(sizeof(tree_node));
	nod_nou->left = NULL;
	nod_nou->right = NULL;
	nod_nou->route_table_entries = NULL;
	return nod_nou;
}

// Routing table structure, taken from the 4th Lab
struct route_table_entry {
	uint32_t prefix;
	uint32_t next_hop;
	uint32_t mask;
	int interface;
};

// Arp table entry, taken from the 4th Lab
struct arp_entry {
	__u32 ip;
	uint8_t mac[6];
};

// Declared the arp table globally, simmilar to 4th Lab for an easier usage
// as well as the number of entries, since i will be reallocating the table 
struct arp_entry *arp_table;
int arp_table_len;

// Funtion to determine the number of 1 bits in a mask, function used in
// inserting an entry in the routing table tree 
int number_of_relevant_bits(uint32_t mask) {
	int bits = 0;
	while (mask > 0) {
		int last_bit = mask & 1;
		if (last_bit == 1) {
			bits++;
		}
		mask = mask >> 1;
	}
	return bits;
}

// Function to find the n'th bit (indexing from 1) of a big endian address
int n_th_bit(uint32_t number, int n) {
	int mask = 1 << (32 - n);
	int result = mask & number;
	if (result == 0) 
		return 0;

	return 1;	
}

// Function to add an entry in the routing table tree, at a given step it takes
// the respective bit and if it is 0, it goes to the left child, if it is 1, it
// moves to the right child, if it is the last relevant bit, add it in the
// current node's list of routing entries
void add_in_tree(tree_node *root, struct route_table_entry entry, int current_bit, int relevant_bits) {
	if (root == NULL) {
		return;
	}
	if (current_bit - 1 == relevant_bits) {
		struct route_table_entry *copied_entry = malloc(sizeof(struct route_table_entry));
		copied_entry->prefix = entry.prefix;
		copied_entry->next_hop = entry.next_hop;
		copied_entry->mask = entry.mask;
		copied_entry->interface = entry.interface;
		root->route_table_entries = cons(copied_entry, root->route_table_entries);
		return;
	}
	int bit_here = n_th_bit(entry.prefix, current_bit);
	if (bit_here == 0) {
		if (root->left != NULL) {
			add_in_tree(root->left, entry, current_bit + 1, relevant_bits);
		}
		else {
			root->left = new_node();
			add_in_tree(root->left, entry, current_bit + 1, relevant_bits);
		}
	}
	else {
		if (root->right != NULL) {
			add_in_tree(root->right, entry, current_bit + 1, relevant_bits);
		}
		else {
			root->right = new_node();
			add_in_tree(root->right, entry, current_bit + 1, relevant_bits);
		}
	}
}

// Debugging function used to print the tree
void print_tree(tree_node *root, int level) {
	if (root == NULL) {
		return;
	}
	if (root->route_table_entries != NULL) {
		list entries = root->route_table_entries;
		while (entries != NULL) {
			struct route_table_entry *entry = (struct route_table_entry*) entries->element;
			printf("%d %d %d %d %d\n", entry->prefix, entry->next_hop, entry->mask, entry->interface, level);
			entries = entries->next;
		}
	}
	print_tree(root->left, level + 1);
	print_tree(root->right, level + 1);
}

// Function used to free the dynamically allocated tree
void free_tree(tree_node *root) {
	if (root == NULL) {
		return;
	}
	free_tree(root->left);
	free_tree(root->right);

	if (root->route_table_entries != NULL) {
		list entries = root->route_table_entries;
		while (entries != NULL) {
			struct route_table_entry *entry = (struct route_table_entry*) entries->element;
			free(entry);
			entries = cdr_and_free(entries);
		}
	}

	free(root);
}

// Function to parse the routing table and insert the entries in the tree
// It attempts to get a line at a time from the file, which will be sepparated
// in 4 different strings, one for the prefix address, one for the nex_hop
// address, one for the mask and one for the interface, the first 3 (addressed)
// will each be separated into 4 parts, for example 192.168.0.1 will be broken
// into 192, 168, 0 and 1, which will be then stored (in big endian) in the
// fields of an entry, which will be added in the tree
void read_table(tree_node *root, char *filename) {
	FILE *file = fopen(filename, "r");
	char buffer[100], *prefix, *next_hop, *mask, *interface;
	char *prefix1, *prefix2, *prefix3, *prefix4;
	char *next_hop1, *next_hop2, *next_hop3, *next_hop4;
	char *mask1, *mask2, *mask3, *mask4;

	if (file == NULL) {
		printf("No file found");
		return;
	}

	while (fgets(buffer, 100, file)) {
		struct route_table_entry entry;
		
		prefix = strtok(buffer, " ");
		next_hop = strtok(NULL, " ");
		mask = strtok(NULL, " ");
		interface = strtok(NULL, " \n");

		prefix1 = strtok(prefix, ".");
		prefix2 = strtok(NULL, ".");
		prefix3 = strtok(NULL, ".");
		prefix4 = strtok(NULL, ".");

		next_hop1 = strtok(next_hop, ".");
		next_hop2 = strtok(NULL, ".");
		next_hop3 = strtok(NULL, ".");
		next_hop4 = strtok(NULL, ".");

		mask1 = strtok(mask, ".");
		mask2 = strtok(NULL, ".");
		mask3 = strtok(NULL, ".");
		mask4 = strtok(NULL, ".");
	
		entry.prefix = htonl(256*256*256*atoi(prefix4) + 256*256*atoi(prefix3) + 256 * atoi(prefix2) + atoi(prefix1));
		entry.next_hop = htonl(256*256*256*atoi(next_hop4) + 256*256*atoi(next_hop3) + 256 * atoi(next_hop2) + atoi(next_hop1));
		entry.mask = htonl(256*256*256*atoi(mask4) + 256*256*atoi(mask3) + 256 * atoi(mask2) + atoi(mask1));
		entry.interface = atoi(interface);

		add_in_tree(root, entry, 1, number_of_relevant_bits(entry.mask));
	}
	
	fclose(file);
}

// Function to iterate through the arp entry vector and find the matching entry
// for which the given ip address equals the entry's ip address
struct arp_entry *get_arp_entry(__u32 ip) {
    for (int i = 0; i < arp_table_len; i++) {
		if (arp_table[i].ip == ip) {
			return &arp_table[i];
		}
	}
    return NULL;
}

// Function to determine whether the given ip address is one of the router's
// interfaces' addresses
// Basically i iterate through the interfaces, 0, 1 and 2, compute their ip
// addresses, parse it since it is a char* into a uint32_t address and if there
// is a match, return 1, else, return 0
int is_destined_for_router(uint32_t destination) {
	for (int i = 0; i < ROUTER_NUM_INTERFACES; i++) {
		char *ip = get_interface_ip(i);
		char *ip1, *ip2, *ip3, *ip4;

		ip1 = strtok(ip, ".");
		ip2 = strtok(NULL, ".");
		ip3 = strtok(NULL, ".");
		ip4 = strtok(NULL, ".");

		uint32_t ipaddr = htonl(256*256*256*atoi(ip4) + 256*256*atoi(ip3) + 256 * atoi(ip2) + atoi(ip1));
		if (htonl(destination) == ipaddr) {
			return 1;
		}
	}
	return 0;
}

// Function to determine the best matching routing entry for a given
// destination's ip address which returns the best matching entry by collateral
// effect
// Basically it is a BST search, considering also the fact that we need the
// longest mask of the found entry, which means that we need the entry that is
// the deepest in our tree (the bigger the level, the more relevant bits the
// entry has, the bigger the mask)
void rtable_get_best_match(tree_node *root, struct route_table_entry **best_entry_so_far, int current_bit, uint32_t destination) {
	if (root == NULL) {
		return;
	}

	// if there are entries in this node, attempt to find one that matches
	// the condition
	if (root->route_table_entries != NULL) {
		list entries = root->route_table_entries;
		int most_bits = 0;
		struct route_table_entry *best_here = NULL;
		while (entries != NULL) {
			struct route_table_entry *entry = (struct route_table_entry*) entries->element;
			if ((htonl(destination) & entry->mask) == entry->prefix) {
				int k = number_of_relevant_bits(entry->mask);
				if (k > most_bits) {
					best_here = entry;
					most_bits = k;
				}
			}
			entries = entries->next;
		}
		// if there is no entry found yet, just replace the null with the
		// one found
		if (*best_entry_so_far == NULL) {
			*best_entry_so_far = best_here;
			if (best_here == NULL) {
			}
		}
		// otherwise, check if it is better than the one already found
		// and update the collateral effect answer
		else if (best_here != NULL && number_of_relevant_bits(best_here->mask) > number_of_relevant_bits((*best_entry_so_far)->mask)) {
			*best_entry_so_far = best_here;
		}
	}

	// recursive calls
	int bit_here = n_th_bit(htonl(destination), current_bit);

	if (bit_here == 0) {
		rtable_get_best_match(root->left, best_entry_so_far, current_bit + 1, destination);
	}
	else {
		rtable_get_best_match(root->right, best_entry_so_far, current_bit + 1, destination);
	}
}

int main(int argc, char *argv[])
{
	packet m;
	int rc;

	init(argc - 2, argv + 2);

	if (argc != 5) {
		printf("Not enough arguments?");
		return 1;
	}

	// initialize the routing entry tree using the by-argument given table
	tree_node *root = new_node();
	read_table(root, argv[1]);

	// initialize the queue used to store packages that cannot be sent yet
	queue packets_queue = queue_create();

	// the router must be working permanently and wait to recieve packages
	while (1) {
		// Recieve a package
		rc = get_packet(&m);
		DIE(rc < 0, "get_message");

		// Extracting all the headers to use them later on
		struct ether_header *eth_hdr = (struct ether_header *)m.payload;
		struct iphdr *ip_hdr = (struct iphdr *)(m.payload + sizeof(struct ether_header));
		struct icmphdr *icmp_hdr = (struct icmphdr *)(m.payload + sizeof(struct ether_header) + sizeof(struct iphdr));
		struct  arp_header *arp_hdr = parse_arp(m.payload);

		// If the package recieved is of IP type, if it is meant for me and
		// it is a ICMP Request, send back (to the package's source station)
		// a ICMP reply, with the corresponding arguments to the api function
		// then drop the package
		if (ntohs(eth_hdr->ether_type) == ETHERTYPE_IP && is_destined_for_router(ip_hdr->daddr) && icmp_hdr->type == 8) {
			send_icmp(ip_hdr->saddr, ip_hdr->daddr, eth_hdr->ether_dhost, eth_hdr->ether_shost, 0, 0,
			m.interface, icmp_hdr->un.echo.id, icmp_hdr->un.echo.sequence);
			continue;
		}

		// If it's an arp request meant for me, I send back an arp reply
		// First I build the ether header with the MAC addres of the original
		// package's sender as this package's destination, and the source set
		// as my interface's MAC address then drop the package
		if (ntohs(eth_hdr->ether_type) == ETHERTYPE_ARP && is_destined_for_router(arp_hdr->tpa) && ntohs(arp_hdr->op) == 1) {
			struct ether_header eth_hdr_aux;
			get_interface_mac(m.interface, eth_hdr_aux.ether_shost);
			build_ethhdr(&eth_hdr_aux, eth_hdr_aux.ether_shost, eth_hdr->ether_shost, htons(ETH_P_ARP));
			send_arp(arp_hdr->spa, arp_hdr->tpa, &eth_hdr_aux, m.interface, ntohs(2));
			continue;
		}

		// If it's an arp reply, update the arp table with informations from
		// the reply, iterate through the packages queue, all those packages
		// from the queue that have the destination address the one from the
		// arp reply send them now, otherwise save them in an auxiliary queue
		// to be able to pun them back in the same order in the main queue
		if (ntohs(eth_hdr->ether_type) == ETHERTYPE_ARP && ntohs(arp_hdr->op) == 2) {
			struct arp_entry entry;

			// Take the ip and MAC addresses from the arp package
			entry.ip = arp_hdr->spa;
			entry.mac[0] = arp_hdr->sha[0];
			entry.mac[1] = arp_hdr->sha[1];
			entry.mac[2] = arp_hdr->sha[2];
			entry.mac[3] = arp_hdr->sha[3];
			entry.mac[4] = arp_hdr->sha[4];
			entry.mac[5] = arp_hdr->sha[5];

			// Update the arp table with the newly created entry
			arp_table_len++;
			arp_table = (struct arp_entry*)realloc(arp_table, arp_table_len * sizeof(struct arp_entry));
			arp_table[arp_table_len - 1] = entry;

			queue aux_queue = queue_create();

			// Iterate through the main queue
			while (!queue_empty(packets_queue)) {
				// Extract first package in the queue and extract its headers
				packet *p = (packet *)queue_deq(packets_queue);
				struct ether_header *eth_hdr_aux = (struct ether_header *)p->payload;
				struct iphdr *ip_hdr_aux = (struct iphdr *)(p->payload + sizeof(struct ether_header));

				// Find this package's best route to destination
				struct route_table_entry* best_route_aux = NULL;
				rtable_get_best_match(root, &best_route_aux, 1, ip_hdr_aux->daddr);

				// Check wether the extracted package is meant for the arp
				// reply's source
				if (htonl(best_route_aux->next_hop) == entry.ip) {
					// If it is, set the headers and send
					memcpy(eth_hdr_aux->ether_dhost, entry.mac, sizeof(entry.mac));
					get_interface_mac(best_route_aux->interface, eth_hdr_aux->ether_shost);
					send_packet(best_route_aux->interface, p);
				}
				// Else, add the package in the auxiliary queue
				else {
					queue_enq(aux_queue, p);
				}
			}
			// Empty the auxiliary queue back into the original one
			while (!queue_empty(aux_queue)) {
				packet *p = (packet *)queue_deq(aux_queue);
				queue_enq(packets_queue, p);
			}
			// Drop the package
			continue;
		}

		// Check whether the time to leave of the package is less or equal to 1
		// which would mean that the router must send a Time Excedeed ICMP
		// package to the recieved package's source then drop the package
		if (ip_hdr->ttl <= 1) {
			send_icmp(ip_hdr->saddr, ip_hdr->daddr, eth_hdr->ether_dhost, eth_hdr->ether_shost, 11, 0,
			m.interface, icmp_hdr->un.echo.id, icmp_hdr->un.echo.sequence);
			continue;
		}

		// Check if the checksum is correct, if it isn't, drop the package
		if (ip_checksum(ip_hdr, sizeof(struct iphdr)) != 0) {
			continue;
		}

		// Decrement the time to leave value, since it passed one more hop and
		// update the checksum of the package by first reseting it to 0
		ip_hdr->ttl -= 1;
		ip_hdr->check = 0;
		ip_hdr->check = ip_checksum(ip_hdr, sizeof(struct iphdr));

		// Find the best possible route for the current package by searching in
		// the routing entries tree and entry that has the first (number of 
		// bits in the mask equal to 1) bits equal to the bits from the prefix
		// of the entry
		struct route_table_entry* best_route = NULL;
		rtable_get_best_match(root, &best_route, 1, ip_hdr->daddr);

		// If there is no possible route to send the package to, send back a
		// Target Unreachable ICMP package then drop the package
		if (best_route == NULL) {
			send_icmp(ip_hdr->saddr, ip_hdr->daddr, eth_hdr->ether_dhost, eth_hdr->ether_shost, 3, 0,
			m.interface, icmp_hdr->un.echo.id, icmp_hdr->un.echo.sequence);
			continue;
		}

		// Try to find an entry in the arp table to find the MAC address of the
		// intended destination to be able to send it further
		struct arp_entry * matching_arp_entry = get_arp_entry(ip_hdr->daddr);

		// If there is no such entry found, send a broadcasted arp request in
		// the "general" direction of the destination, the next hop towards the
		// destination
		if (matching_arp_entry == NULL) {
			struct ether_header eth_hdr_aux;

			// Build the ether header in order to send the package forward,
			// First set the source MAC address from the interface where it
			// will be sent
			get_interface_mac(best_route->interface, eth_hdr_aux.ether_shost);

			// Set the destination MAC to broadcast
			eth_hdr_aux.ether_dhost[0] = 255;
			eth_hdr_aux.ether_dhost[1] = 255;
			eth_hdr_aux.ether_dhost[2] = 255;
			eth_hdr_aux.ether_dhost[3] = 255;
			eth_hdr_aux.ether_dhost[4] = 255;
			eth_hdr_aux.ether_dhost[5] = 255;
			// Set the type to ARP
			eth_hdr_aux.ether_type = ntohs(ETH_P_ARP);

			// Since get_interface_ip returns a char *, parse it to a little
			// endian ip address and use it as source ip address
			char *ip = get_interface_ip(best_route->interface);
			char *ip1, *ip2, *ip3, *ip4;
			ip1 = strtok(ip, ".");
			ip2 = strtok(NULL, ".");
			ip3 = strtok(NULL, ".");
			ip4 = strtok(NULL, ".");

			uint32_t here_address = 256*256*256*atoi(ip4) + 256*256*atoi(ip3) + 256*atoi(ip2) + atoi(ip1);
			
			// Send the arp request to the next_hop station
			send_arp(htonl(best_route->next_hop), here_address, &eth_hdr_aux, best_route->interface, ntohs(1));

			// Make a copy of the original package and enqueue it for later
			// sending then drop the package
			packet *to_pack = malloc(sizeof(packet));
			memcpy(to_pack, &m, sizeof(packet));
			queue_enq(packets_queue, to_pack);
			continue;
		}
		// If the package can be sent, update the MAC addresses of the packages
		memcpy(eth_hdr->ether_dhost, matching_arp_entry->mac, sizeof(matching_arp_entry->mac));
		get_interface_mac(best_route->interface, eth_hdr->ether_shost);

		// Send the package
		send_packet(best_route->interface, &m);
	}
	// Free the dynamically allocated memory
	free_tree(root);
	free(arp_table);
}
