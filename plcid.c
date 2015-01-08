#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <termios.h>
#include <unistd.h>
#include <errno.h>

int plc_port = 0;

struct speed_map {
	unsigned short speed;
	unsigned short value;
};

static const struct speed_map speeds[] = {
	{B0, 0},
	{B50, 50},
	{B75, 75},
	{B110, 110},
	{B134, 134},
	{B150, 150},
	{B200, 200},
	{B300, 300},
	{B600, 600},
	{B1200, 1200},
	{B1800, 1800},
	{B2400, 2400},
	{B4800, 4800},
	{B9600, 9600},
#ifdef B19200
	{B19200, 19200},
#elif defined(EXTA)
	{EXTA, 19200},
#endif
#ifdef B38400
	{B38400, 38400/256 + 0x8000U},
#elif defined(EXTB)
	{EXTB, 38400/256 + 0x8000U},
#endif
#ifdef B57600
	{B57600, 57600/256 + 0x8000U},
#endif
#ifdef B115200
	{B115200, 115200/256 + 0x8000U},
#endif
#ifdef B230400
	{B230400, 230400/256 + 0x8000U},
#endif
#ifdef B460800
	{B460800, 460800/256 + 0x8000U},
#endif
#ifdef B921600
	{B921600, 921600/256 + 0x8000U},
#endif
};

enum { NUM_SPEEDS = sizeof(speeds)/sizeof(speeds[0]) };

static unsigned tty_baud_to_value(speed_t speed)
{
	int i = 0;

	do {
		if (speed == speeds[i].speed) {
			if (speeds[i].value & 0x8000U) {
				return ((unsigned long) (speeds[i].value) & 0x7fffU) * 256;
			}
			return speeds[i].value;
		}
	} while (++i < NUM_SPEEDS);

	return 0;
}

static speed_t tty_value_to_baud(unsigned int value)
{
	int i = 0;

	do {
		if (value == tty_baud_to_value(speeds[i].speed)) {
			return speeds[i].speed;
		}
	} while (++i < NUM_SPEEDS);

	return (speed_t) - 1;
}

int plc_open_port(char *port, speed_t baud)
{   
    /* open IT900 serial port */
    plc_port = open(port, O_RDWR | O_NOCTTY);
    if(plc_port < 0)
    {
        return errno;
    }
    
    /* set serial parameters */
    struct termios tio;
    tcgetattr(plc_port, &tio);
    
    tio.c_iflag = IGNBRK;
    tio.c_oflag = 0;
    tio.c_lflag = 0;        /* raw input mode */
    tio.c_cc[VTIME] = 0;    /* no read timer */
    tio.c_cc[VMIN] = 1;     /* block for minimum 1 byte */
    
    tio.c_cflag &= ~(CSIZE | CSTOPB | PARENB | PARODD | CRTSCTS);
    tio.c_cflag |=  CS8 | CLOCAL;
    
    cfsetispeed(&tio, baud);
    cfsetospeed(&tio, baud);
    
    tcsetattr(plc_port, TCSANOW, &tio);
    
    return 0;
}

void plc_close_port()
{
    if(plc_port)
    {
        close(plc_port);
    }
    plc_port = 0;
}

int plc_nop()
{
    int i,err;
    char request[] = {0xCA, 0x02, 0x00, 0x00, 0x00, 0x02};
    char response[7];
    char expected[] = {0xCA, 0x03, 0x00, 0x01, 0x00, 0x01, 0x05};
    
    err = write(plc_port, request, 6);
    if(err < 0)
    {
        return errno;
    }
    
    err = read(plc_port, response, 7);
    if(err < 0)
    {
        return errno;
    }
    
    for(i = 0; i < 7; i++)
    {
        if(response[i] != expected[i])
        {
            return -1;
        }
    }
    
    return 0;
}

int plc_get_id(unsigned short *netid, unsigned short *id)
{
    int i,err;
    char request[] = {0xCA, 0x07, 0x00, 0x00, 0x42, 0x06, 0x18, 0x00, 0x02, 0x00, 0x69};
    char response[11];
    char expected[] = {0xCA, 0x07, 0x00, 0x01, 0x42, 0x01};
    unsigned char checksum = 0x4B;
    
    err = write(plc_port, request, 11);
    if(err < 0)
    {
        return errno;
    }
    
    err = read(plc_port, response, 11);
    if(err < 0)
    {
        return errno;
    }
    
    for(i = 0; i < 6; i++)
    {
        if(response[i] != expected[i])
        {
            return -1;
        }
    }
    
    for(i = 6; i < 10; i++)
    {
        checksum += response[i];
    }
    
    if(checksum != response[10])
    {
        return -1;
    }
    
    *netid = response[6];
    *netid += ((unsigned short)response[7]) << 8;
    *id = response[8];
    *id += ((unsigned short)response[9]) << 8;
    
    return 0; 
}

int main(int argc, char **argv)
{
    unsigned short netid, id;
    speed_t baud;
    int tty_value = -1;
    
    if(argc != 3)
    {
        fprintf(stderr,"Usage: plcid DEVICE BAUD\n");
        return 1;
    }
    
    char *port = argv[1];
    
    tty_value = atoi(argv[2]);
	if(tty_value < 0)
	{
		fprintf(stderr,"Invalid baud rate: %s\n",argv[2]);
		return 1;
	}
	baud = tty_value_to_baud(tty_value);
	if(baud < 0)
	{
		fprintf(stderr,"Invalid baud rate: %s\n",argv[2]);
		return 1;
	}
    
    if(plc_open_port(port,baud))
    {
        fprintf(stderr,"Failed to open port\n");
        plc_close_port();
        return 1;
    }
    
    if(plc_nop())
    {
        fprintf(stderr,"NOP failed\n");
        plc_close_port();
        return 1;
    }
    
    if(plc_get_id(&netid,&id))
    {
        fprintf(stderr,"Failed to get ID\n");
        plc_close_port();
        return 1;
    }
    
    printf("%d.%d\n",netid,id);
    
    plc_close_port();
    
    return 0;
}

