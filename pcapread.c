/* Demonstration program of reading packet trace files recorded by pcap
 * (used by tshark and tcpdump) and dumping out some corresponding information
 * in a human-readable form.
 *
 * Note, this program is limited to processing trace files that contains
 * UDP packets.  It prints the timestamp, source port, destination port,
 * and length of each such packet.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/types.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>

#include <pcap.h>
#include "disorder.h"
#include "pcapread.h"

int main(int argc, char *argv[])
{
	pcap_t *pcap;
	const unsigned char *packet;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr header;


	/* options */
	char *filename = "";
	unsigned pktnum = 0;
	bool show_errors = true;

	/* Get options */
	int c;
	opterr = 0; // turn off getopt error
	while ((c = getopt (argc, argv, "f:n:eh")) != -1)
	{
		switch (c)
		{
			case 'f':
				filename = (char *)calloc(strlen(optarg)+1,sizeof(char));
				strcpy(filename,optarg);
				filename[strlen(optarg)+1] = '\0'; // secure ending of c-string
				break;
			case 'n':
				pktnum = strtoul(optarg,NULL,10);
				break;
			case 'e':
				show_errors = false;
				break;
			case 'h':
				print_help();
				exit(0);
			case '?':
				fprintf(stderr, "Unknown options '%c'.\n",optopt);
				break;
			default:
				abort ();
		}
	}

	/* If no get filename parameter */
	if(strlen(filename)==0){
		fprintf(stderr, "\nError: no file for parsing\n");
		print_help();
		//free(filename);
		exit(1);
	}else{
		fprintf(stderr, "Read file: %s...\n", filename);
	}

	/* Packet number check */
	if(pktnum > 0){
		fprintf(stderr, "Set packet limit: %u packets\n", pktnum );
	}

	/* Open pcap file */
	if ((pcap = pcap_open_offline(filename, errbuf)) == NULL){
		fprintf(stderr, "\nError: can't read pcap file: %s\n", errbuf);
		free(filename);
		exit(1);
	}


	/* Now just loop through extracting packets as long as we have
	 * some to read.
	 */
	bool unlim = ( pktnum == 0 );
	unsigned int pkt_cnt = 0;
	unsigned int index = 0;
	while ((packet = pcap_next(pcap, &header)) != NULL) {
	    if ( unlim || ( pktnum-- > 0 ) )
	      {
		dump_packet( ++index, packet, &header, show_errors);
	      } else {
		break;
	      }
	}

	// terminate
	return 0;
}

/* dump_packet() */
void dump_packet( unsigned int index, const unsigned char *packet, struct pcap_pkthdr *header, bool show_errors)
{
	struct ip *ip;
	struct udphdr *udp;
	struct tcphdr *tcp;
	unsigned int IP_header_length;
	struct timeval ts = header->ts;
	unsigned int capture_len = header->caplen;
	uint byte_count[256] = {};

	struct ether_header *eth_hdr;

	/* For simplicity, we assume Ethernet encapsulation. */

	if (capture_len < sizeof(struct ether_header)) {
		/* We didn't even capture a full Ethernet header, so we
		 * can't analyze this any further.
		 */
		too_short(ts, "Error: Short Ethernet Header");
		return;
	}

	eth_hdr = (struct ether_header*)malloc(sizeof(struct ether_header));

	/* Skip over the Ethernet header. */
	memcpy(&eth_hdr,&packet,sizeof(struct ether_header));

/*
 * example mac out

	fprintf(stderr,
		"To:      %02X:%02X:%02X:%02X:%02X:%02X\n",
		eth_hdr->ether_dhost[0], eth_hdr->ether_dhost[1], eth_hdr->ether_dhost[2],
		eth_hdr->ether_dhost[3], eth_hdr->ether_dhost[4], eth_hdr->ether_dhost[5]
	    );
*/

	packet += sizeof(struct ether_header);
	capture_len -= sizeof(struct ether_header);

	if (capture_len < sizeof(struct ip))
	{ /* Didn't capture a full IP header */
		too_short(ts, "Error: Short IP Header");
		return;
	}

	ip = (struct ip*)malloc(sizeof(struct ip));
	memcpy(&ip,&packet,sizeof(struct ip));

	IP_header_length = ip->ip_hl * 4;	/* ip_hl is in 4-byte words */

/*
 * example addr out

	char *sip = inet_ntoa(ip->ip_src);
	fprintf(stderr,"sIP:%s\n ",sip);
*/
	if (capture_len < IP_header_length)
	{ /* didn't capture the full IP header including options */
		too_short(ts, "Error: Short IP Header with options");
		return;
	}

	if ( ip->ip_p != IPPROTO_UDP && ip->ip_p != IPPROTO_TCP)
	{
		if(show_errors) problem_pkt(ts, "Error: non-UDP-TCP packet");
		return;
	}

	/* Skip over the IP header to get to the UDP header. */
	packet += IP_header_length;
	capture_len -= IP_header_length;

	if ( ip->ip_p == IPPROTO_UDP ) {
	  udp = (struct udphdr*) packet;
	  packet += sizeof( struct udphdr );
	  capture_len -= sizeof( struct udphdr );
	} else {
	  tcp = (struct tcphdr*) packet;
	  packet += tcp->doff * 4;
	  capture_len -= tcp->doff * 4;
	}

	uint i = 0;
	while(i < capture_len){
	    byte_count[packet[i++]]++; // increment of array element, which has no = byte

	}

/*
	uint j = 0;
	for(;j<256;j++){s
	   fprintf(stderr,"byte: %3u - %u\n",j,byte_count[j]);
	}
*/
	if ( capture_len > 0 ) {
	  double e = shannon_H( packet, capture_len );
	  double me = get_max_entropy();

	  printf( "n %6u \t l %4u \t e %f \t me %f \t ts %3u\n",
		  index, capture_len, e, me, get_num_tokens() );
	}

}


/* Note, this routine returns a pointer into a static buffer, and
 * so each call overwrites the value returned by the previous call.
 */
const char *timestamp_string(struct timeval ts)
{
	static char timestamp_string_buf[256];

	sprintf(timestamp_string_buf, "%d.%06d",
		(int) ts.tv_sec, (int) ts.tv_usec);

	return timestamp_string_buf;
}

void problem_pkt(struct timeval ts, const char *reason)
{
	fprintf(stderr, "%s: %s\n", timestamp_string(ts), reason);
}

void too_short(struct timeval ts, const char *truncated_hdr)
{
	fprintf(stderr, "packet with timestamp %s is truncated and lacks a full %s\n",
		timestamp_string(ts), truncated_hdr);

}

void print_help(void)
{
	fprintf(stderr,
		"\n"
		"Usage: %s -f <pcap-file> [-n <num> -eh]\n"
		"\n"
		"\t-f <pcap-file> - pcap file full path\n"
		"\t-n <num> - packet number for parse\n"
		"\t-e - ignore errors like 'non-UDP-TCP packet'\n"
		"\t-h - show this help\n"
		"\n",
		"pcapread"
	);
}
