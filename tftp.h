#ifndef __TFTP_H
#define __TFTP_H

#include "tftp_types.h"

/* tftp handle init. fill in filename */
int
tftp_init(tftp **handle);

/* catch packet, fill in data using fd */
void
tftp_run(tftp **handle, const char *protodata, int len);

/* done callback. do whatever you want */
void
tftp_callback(tftp **handle);

/* destory handle */
int 
tftp_destory(tftp **handle);

/* according to udp format, decode udp */
int
decode_tftp(const char *header_start);

/* dump packet data, for debug */
void 
dump(const char *data_buffer, const unsigned int length);

/* caught packet; protodata points to udp payload, len being its len. */
void
caught_packet(const struct pcap_pkthdr *cap_header, const u_char *packet, const char **protodata, int *len);

/* fill handle with filename */
void
fill_handle(tftp **handle, const char *protodata, int len);

#endif  /* __TFTP_H */
