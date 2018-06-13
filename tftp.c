#include <stdlib.h>
#include <sys/types.h>
#include <pcap.h>
#include <netint/ip.h>
#include <stdio.h>
#include <string.h>
#include "tftp_types.h"


int
tftp_init(tftp **handle)
{
	*handle = (tftp *)malloc(sizeof(tftp));

	if (!*handle) {
		return (-1);
	} else {
		memset(*handle, 0, sizeof(tftp)); // set all 0
		strcpy((*handle)->filepath, "/dev/shm");
		return (0);
	}
}

void
tftp_run(tftp **handle, const char *protodata, int len)
{
	if (len <= 0) {
		return;
	}
	int packet_type;
	const char *ptr_file_data;
	int data_len;
	int data_writen = 0;

	packet_type = decode_tftp(protodata);  // see what type is. REQUEST fill handle, DATA save, ACK ignore

	if (packet_type == R_REQUEST || 
	    packet_type == W_REQUEST) {   // fill handle. such as filename. it's the only thing....
		fill_handle(handle, protodata, len);
	

		// now filename filled up. open file 
		char file_dest[512+512];
		strcpy(file_dest, (*handle)->filepath);
		strcat(file_dest, (*handle)->filename);
		(*handle)->fd = open(file_dest,
				O_RDWR | O_CREAT | O_APPEND,
				S_IRUSR | S_IWUSR);
		if ((*handle)->fd == -1) {
			printf("ERROR: file open error!\n");
			return;

		}
		// one packet contain only one useful info. ethier filename, or data.
		// since fill filename done, there nothing remains.
		return;
	
	} else if (packet_type == DATA) {
	       ptr_file_data = protodata + 4;   // 4 is tftp header len.	
	       data_len = len - 4;

	       while (data_writen < data_len) {
		       write((*handle)->fd, ptr_file_data,1);
		       data_writen++;
		       ptr_file_data++;
	       }
	       if (data_len != 512) {   // last packet
		       close((*handle)->fd);
		       tftp_callback(handle);
	       }
	}
}

void
tftp_callback(tftp **handle)
{
	/* fill in what you want to the file */
}

int 
tftp_destory(tftp **handle)
{
	if (!*handle) {    // if alreay free. an issue.
		return (-1);
	}

	free(*handle);
	*handle = NULL;

	return (0);
}

int 
decode_tftp(const char *header_start)
{
	char s_type[3];
	int type;

	s_type[0] = header_start[0];
	s_type[1] = header_start[1];
	s_type[2] = '\0';
	type = atoi(s_type);

	return type;
}

void
caught_packet(const struct pcap_pkthdr *cap_header, const u_char *packet, const char **protodata, int *len)
{
	int total_header_size, pkt_data_len;
	u_char *pkt_data;

	total_header_size = 14 + sizeof(struct iphdr) + 8; // 14 ethernet, ip hdr, plus 8 udp
	pkt_data = (u_char *)packet + total_header_size;  // point ot tftp (its header, and tftp data)
	pkt_data_len = cap_header->len - total_header_size;

	*protodata = (const char *)pkt_data;
	*len = pkt_data_len;
}

void
fill_handle(tftp **handle, const char *protodata, int len)
{
	int filename_len;
	char *filename_ptr;
	int i = 0;

	filename_len = len - 2 - 6;   // 2 is opcode; 6 is type;
	filename_ptr = protodata + 2;  // now filename_ptr points to filename section

	while (filename_len > 0) {
		((*handle)->filename)[i] = filename_ptr[i];
		i++;
		filename_len--;
	}
	((*handle)->filename)[i] = '\0';

}	


void
dump(const char *data_buffer, const unsigned int length)
{
	unsigned char byte;
	unsigned int i, j;
	for (i = 0; i < length; i++) {
		byte = data_buffer[i];
		printf("%02x ", data_buffer[i]);
		if (((i%16) == 15) || (i == length-1)) {
			for (j = 0; j < 15 - (i % 16); j++) 
				printf("  ");
			printf("| ");
			for (j=(i-(i%16)); j <= i; j++) {
				byte = data_buffer[j];
				if ((byte > 31) && (byte < 127))
					printf("%c", byte);
				else
					printf(".");
			}
			printf("\n");
		} // end if
	} //end for
}


