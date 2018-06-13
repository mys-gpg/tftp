#ifndef __TFTP_TYPES_H
#define __TFTP_TYPES_H

typedef enum {
	R_REQUEST = 1,
	W_REQUEST = 2,
	DATA      = 3,
	ACK       = 4
};

typedef struct tftp_handle {
	char filename[512];
	char filepath[512];
	int fd;
	
} tftp;

#endif   /* __TFTP_TYPES_H */
