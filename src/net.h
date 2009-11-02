#ifndef _NET_H
#define _NET_H

#ifndef _STD_TYPES
#define _STD_TYPES

#define uchar   unsigned char
#define uint    unsigned int
#define ulong   unsigned long int

#endif

#define ERR_NET_UNKNOWN_HOST            0x1000
#define ERR_NET_CONNECT_FAILED          0x2000
#define ERR_NET_SOCKET_FAILED           0x3000
#define ERR_NET_BIND_FAILED             0x4000
#define ERR_NET_LISTEN_FAILED           0x5000
#define ERR_NET_ACCEPT_FAILED           0x6000
#define ERR_NET_READ_FAILED             0x7000
#define ERR_NET_CONN_RESET              0x8000
#define ERR_NET_WRITE_FAILED            0x9000

/*
 * Initiate a TCP connection with hostname:port
 */
int net_connect( int *server_fd, char *hostname, uint port );

/*
 * Create a listening socket on ip:port. Set bind_ip
 * to NULL to listen on all network interfaces.
 */
int net_bind( int *server_fd, char *bind_ip, uint port );

/*
 * Accept a connection from a remote client
 */
int net_accept( int server_fd, int *client_fd, ulong *client_ip );

/*
 * Return 0 if data is available at the transport layer,
 * or 1 otherwise (in which case read() will block).
 */
int net_is_read_blocking( int fd );

/*
 * Loop until "len" characters have been read.
 */
int net_read_all( int read_fd, uchar *buf, uint len );

/*
 * Loop until "len" characters have been written.
 */
int net_write_all( int write_fd, uchar *buf, uint len );

/*
 * Gracefully shutdown the connection
 */
void net_close( int sock_fd );

#endif /* net.h */