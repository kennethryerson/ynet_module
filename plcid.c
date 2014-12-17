#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <termios.h>
#include <unistd.h>
#include <errno.h>

int plc_port = 0;

int plc_open_port(char *port)
{
    unsigned int baud = B115200;
    
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
    
    if(argc != 2)
    {
        fprintf(stderr,"Usage: plcid DEVICE\n");
        return 1;
    }
    
    char *port = argv[1];
    
    if(plc_open_port(port))
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

