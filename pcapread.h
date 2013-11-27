#ifndef PCAPREAD_H
#define PCAPREAD_H

 /* We've included the UDP header struct for your ease of customization.
  * For your protocol, you might want to look at netinet/tcp.h for hints
  * on how to deal with single bits or fields that are smaller than a byte
  * in length.
  *
  * Per RFC 768, September, 1981.
  */

void dump_packet(unsigned int index, const unsigned char *packet, struct pcap_pkthdr *header, bool show_errors );

/* Some helper functions, which we define at the end of this file. */

/* Returns a string representation of a timestamp. */
const char *timestamp_string(struct timeval ts);

/* Report a problem with dumping the packet with the given timestamp. */
void problem_pkt(struct timeval ts, const char *reason);

/* Report the specific problem of a packet being too short. */
void too_short(struct timeval ts, const char *truncated_hdr);

/* Print help message */
void print_help(void);


#endif // PCAPREAD_H
