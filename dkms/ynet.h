/*
 * ynet.h	Define the Y-net device driver interface and constants.
 *
 * Version:	@(#)ynet.h	0.2.0
 *
 * Author:	Kenneth Ryerson
 */
#ifndef _LINUX_YNET_H
#define _LINUX_YNET_H

/* Y-net configuration. */
#define YN_MTU		1400
#define YNET_DATA_LEN	1472
#define YNET_TIMEOUT	(2*HZ)

/* Y-net protocol characters. */
#define YNET_ATTENTION	0xCA
#define YNET_ESC        0xDB

/* Y-net packet types */
#define YNET_PACKET_TYPE_REQUEST    0x00
#define YNET_PACKET_TYPE_RESPONSE   0x01
#define YNET_PACKET_TYPE_INDICATION 0x02

/* Y-net service types */
#define YNET_SERVICE_TYPE_SHIFT			5

#define YNET_SERVICE_TYPE_EMBEDDED		0
#define YNET_SERVICE_TYPE_STACK			1
#define YNET_SERVICE_TYPE_CONFIG_MON	2
#define YNET_SERVICE_TYPE_NL_DATA		3
#define YNET_SERVICE_TYPE_MANAGEMENT_SA	5

/* Y-net opcodes */
#define YNET_OPCODE_NOP                                             0x00
#define YNET_OPCODE_GET_VERSION                                     0x01
#define YNET_OPCODE_GET_FREE_MEMORY                                 0x02
#define YNET_OPCODE_WELCOME                                         0x04
#define YNET_OPCODE_READ_FROM_NVM                                   0x05
#define YNET_OPCODE_WRITE_TO_NVM                                    0x06

#define YNET_OPCODE_RESET                                           0x20
#define YNET_OPCODE_GO_ONLINE                                       0x22
#define YNET_OPCODE_GO_OFFLINE                                      0x23

#define YNET_OPCODE_SET_PREDEFINED_PARAMETERS                       0x40
#define YNET_OPCODE_SET_DEVICE_PARAMETERS                           0x41
#define YNET_OPCODE_GET_DEVICE_PARAMETERS                           0x42
#define YNET_OPCODE_SAVE_DEVICE_PARAMETERS                          0x43
#define YNET_OPCODE_REMOTE_PARAMETERS_CHANGED                       0x4C

#define YNET_OPCODE_TX_PACKET                                       0x60
#define YNET_OPCODE_GET_NC_DATABASE_SIZE                            0x65
#define YNET_OPCODE_RX_PACKET                                       0x68
#define YNET_OPCODE_GET_NODE_INFORMATION                            0x69
#define YNET_OPCODE_DELETE_NODE_INFORMATION                         0x6A

#define YNET_OPCODE_ADMISSION_APPROVAL_RESPONSE_FROM_APPLICATION    0xA4
#define YNET_OPCODE_LEAVE_NETWORK                                   0xA6
#define YNET_OPCODE_CONNECTIVITY_STATUS_WITH_RS                     0xB1
#define YNET_OPCODE_NODE_LEFT_NETWORK                               0xB3
#define YNET_OPCODE_GET_ADMISSION_APPROVAL_FROM_APPLICATION         0xB8
#define YNET_OPCODE_ADMISSION_REFUSE                                0xB9
#define YNET_OPCODE_CONNECTED_TO_NC                                 0xBA
#define YNET_OPCODE_DISCONNECTED_FROM_NC                            0xBB
#define YNET_OPCODE_NEW_CONNECTION_TO_NC                            0xBE
#define YNET_OPCODE_NETWORK_ID_ASSIGNED                             0xBF

/* Y-net data packet flags */
#define YNET_PACKET_DATA_TYPE_INTRABCAST    0x00
#define YNET_PACKET_DATA_TYPE_INTRAUCAST    0x01
#define YNET_PACKET_DATA_TYPE_INTRAUCASTSN  0x02
#define YNET_PACKET_DATA_TYPE_INTERBCAST    0x03
#define YNET_PACKET_DATA_TYPE_INTERUCAST    0x04
#define YNET_PACKET_DATA_TTL                0x08

#define YNET_PACKET_DATA_PRIORITY_NORMAL    0x00
#define YNET_PACKET_DATA_PRIORITY_HIGH      0x01
#define YNET_PACKET_DATA_PRIORITY_EMERGENCY 0x02

#define YNET_PACKET_DATA_NOACK              0x00
#define YNET_PACKET_DATA_ACK                0x01

/* Y-net modulation types */
#define YNET_PACKET_MODULATION_AUTO         0x1F
#define YNET_PACKET_MODULATION_DCSKT_0      0x00
#define YNET_PACKET_MODULATION_DCSKT_1      0x01
#define YNET_PACKET_MODULATION_DCSKT_2      0x02
#define YNET_PACKET_MODULATION_DCSKT_3      0x03
#define YNET_PACKET_MODULATION_DCSKT_4      0x04
#define YNET_PACKET_MODULATION_DCSKT_5      0x05
#define YNET_PACKET_MODULATION_DCSKT_6      0x06
#define YNET_PACKET_MODULATION_DCSKT_7      0x07
#define YNET_PACKET_MODULATION_DCSKT_8      0x08
#define YNET_PACKET_MODULATION_DCSKT_9      0x09
#define YNET_PACKET_MODULATION_DCSKT_10     0x0A
#define YNET_PACKET_MODULATION_DCSKT_11     0x0B
#define YNET_PACKET_MODULATION_DCSKT_12     0x0C
#define YNET_PACKET_MODULATION_DCSKT_TD1    0x0D
#define YNET_PACKET_MODULATION_DCSKT_TD2    0x0E
#define YNET_PACKET_MODULATION_DCSKT_TD3    0x0F
#define YNET_PACKET_MODULATION_DCSKT_TD4    0x10
#define YNET_PACKET_MODULATION_DCSKT_TD5    0x11
#define YNET_PACKET_MODULATION_DCSKT_TD6    0x12
#define YNET_PACKET_MODULATION_DCSKT_TD7    0x13
#define YNET_PACKET_MODULATION_DCSKT_TD8    0x14
#define YNET_PACKET_MODULATION_DCSKT_TD9    0x15
#define YNET_PACKET_MODULATION_DCSKT_TD10   0x16
#define YNET_PACKET_MODULATION_DCSKT_SM     0x19
#define YNET_PACKET_MODULATION_DCSKT_RM     0x1A
#define YNET_PACKET_MODULATION_DCSKT_ERM    0x1B

/* Y-net response values */
#define YNET_RESPONSE_STATUS_FAILED                 0x00
#define YNET_RESPONSE_STATUS_SUCCESS                0x01

#define YNET_RESPONSE_STATUS_RESET_NO_EEPROM        06
#define YNET_RESPONSE_STATUS_RESET_SUCCESS          07
#define YNET_RESPONSE_STATUS_RESET_FACTORY_DEFAULTS 08
#define YNET_RESPONSE_STATUS_RESET_FATAL_ERROR      32
#define YNET_RESPONSE_STATUS_RESET_AUTO_ONLINE      64
#define YNET_RESPONSE_STATUS_RESET_SAFE_MODE        66

#define YNET_RESPONSE_DATA_RESULT1_ACCEPTED          0x00
#define YNET_RESPONSE_DATA_RESULT1_NO_MEMORY         0x01
#define YNET_RESPONSE_DATA_RESULT1_FATAL_ERROR       0x02
#define YNET_RESPONSE_DATA_RESULT1_UNKNOWN_NODE      0x03

#define YNET_RESPONSE_DATA_RESULT2_SUCCESS           0x00
#define YNET_RESPONSE_DATA_RESULT2_NA                0x01
#define YNET_RESPONSE_DATA_RESULT2_NACK              0x02
#define YNET_RESPONSE_DATA_RESULT2_NO_RESOURCES      0x03
#define YNET_RESPONSE_DATA_RESULT2_BLOCKED           0x04
#define YNET_RESPONSE_DATA_RESULT2_UNKNOWN_ERROR     0x05

#define YNET_APPLICATION_PACKET_TYPE_CONNECT         0x10
#define YNET_APPLICATION_PACKET_TYPE_DISCONNECT      0x20
#define YNET_APPLICATION_PACKET_TYPE_DATA            0x40
#define YNET_APPLICATION_PACKET_TYPE_ACK             0x80

struct ynet
{
	int magic;

	/* Various fields. */
	struct tty_struct	*tty;		/* ptr to TTY structure		*/
	struct net_device	*dev;		/* easy for intr handling	*/
	spinlock_t			lock;

	/* These are pointers to the malloc()ed frame buffers. */
	unsigned char		*rbuff;		/* receiver buffer */
	int					rcount;		/* received chars counter */
	unsigned char		*rspbuff;	/* response buffer */
	int					rspcount;	/* response chars counter */
	unsigned char		*xbuff;		/* transmitter buffer */
	unsigned char		*xhead;		/* pointer to next byte to XMIT */
	int					xleft;		/* bytes left in XMIT queue */

	/* Detailed Y-net statistics. */

	int					mtu;		/* Our mtu (to spot changes!)   */
	int					buffsize;	/* Max buffers sizes            */
	
	unsigned long		rxstate;	/* Receiver state */
#define YNS_ATTN		0			/* Attention state */
#define YNS_LENL		1			/* Length LSB */
#define YNS_LENH		2			/* Length MSB */
#define YNS_TYPE		3			/* Packet type */
#define YNS_OPCODE		4			/* Packet opcode */
#define YNS_PAYLOAD		5			/* Payload */
#define YNS_CHKSUM		6			/* Checksum byte */

	unsigned long		flags;		/* Flag values/ mode etc	 */
#define YNF_INUSE		0			/* Channel in use            */
#define YNF_ERROR		1			/* Parity, etc. error        */
#define YNF_RESP		2			/* Response received flag    */
#define YNF_DATARX		3			/* Data packet received flag */
#define YNF_RST			4			/* Reset flag				 */
#define YNF_ESCAPE      5           /* Escape flag               */
	
	unsigned short		rxlength;	/* expected incoming packet length */
	unsigned short		plidx;		/* current payload receive index */
	unsigned char		rxtype;		/* incoming packet type */
	unsigned char		rxopcode;	/* incoming packet opcode */
	unsigned char		checksum;	/* incoming packet's checksum */
	unsigned char		leased;
	dev_t				line;
	pid_t				pid;
};

#define YNET_MAGIC 0x422A

#endif	/* _LINUX_YNET_H */

