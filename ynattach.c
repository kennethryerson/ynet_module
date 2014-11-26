/* vi: set sw=4 ts=4: */
/*
 * Attaches a Y-net protocol serial device to a network interface
 * Requires ynet kernel module
 *
 * Author: Kenneth Ryerson (kryerson at vermeer dot com)
 *
 * Licensed under GPLv2 or later, see file LICENSE in this source tree.
 *
 * Based on slattach
 *
 */

#include <stdlib.h>
#include <stdio.h>
#include <termios.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <malloc.h>
#include <signal.h>

/* must match the define in patched linux/tty.h */
#define N_YNET 25

static int handle;
static int saved_disc;
static struct termios saved_state;

static void syntax()
{
	printf("ynattach [-c PROG] [-s SPEED] DEVICE\n");
}

static void usage()
{
	syntax();
	printf("Attach network interface to Y-net serial device\n");
	printf("    -s SPD  Set line speed\n");
	printf("    -c PROG Run PROG when the line is hung up\n");
}

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

/*
 * Save tty state and line discipline
 *
 * It is fine here to bail out on errors, since we haven modified anything yet
 */
static void save_state(void)
{
	/* Save line status */
	if (tcgetattr(handle, &saved_state) < 0)
	{
		fprintf(stderr,"Error getting state\n");
		exit(EXIT_FAILURE);
	}

	/* Save line discipline */
	if(ioctl(handle, TIOCGETD, &saved_disc) < 0)
	{
		fprintf(stderr,"Error getting line discipline\n");
		exit(EXIT_FAILURE);
	}
}

static int set_termios_state_or_warn(struct termios *state)
{
	int ret;

	ret = tcsetattr(handle, TCSANOW, state);
	if (ret < 0) {
		fprintf(stderr,"Error setting state\n");
		return 1; /* used as exitcode */
	}
	return 0;
}

/*
 * Restore state and line discipline for ALL managed ttys
 *
 * Restoring ALL managed ttys is the only way to have a single
 * hangup delay.
 *
 * Go on after errors: we want to restore as many controlled ttys
 * as possible.
 */
static void restore_state_and_exit(int exitcode)
{
	struct termios state;

	/* Restore line discipline */
	if (ioctl(handle, TIOCSETD, &saved_disc) < 0)
	{
		fprintf(stderr,"Failed to restore line discipline\n");
		exitcode = 1;
	}

	/* Hangup */
	memcpy(&state, &saved_state, sizeof(state));
	cfsetispeed(&state, B0);
	cfsetospeed(&state, B0);
	if (set_termios_state_or_warn(&state))
		exitcode = 1;
	sleep(1);

	/* Restore line status */
	if (set_termios_state_or_warn(&saved_state))
		exit(EXIT_FAILURE);
	
	close(handle);

	exit(exitcode);
}

/*
 * Set tty state, line discipline
 */
static void set_state(struct termios *state)
{
	int disc;

	/* Set line status */
	if (set_termios_state_or_warn(state))
		restore_state_and_exit(EXIT_FAILURE);
	/* Set line discipline (N_YNET always) */
	disc = N_YNET;
	if (ioctl(handle, TIOCSETD, &disc) < 0)
	{
		fprintf(stderr,"Failed to set line discipline\n");
		restore_state_and_exit(EXIT_FAILURE);
	}
}

static void sig_handler(int signo)
{
	restore_state_and_exit(EXIT_SUCCESS);
}

int main(int argc, char **argv)
{
	int i, c, opt;
	struct termios state;
	const char *baud_str;
	int baud_code = -1;   /* Line baud rate (system code) */
    pid_t pid, sid;

	enum {
		OPT_s_baud   = 1 << 0
	};

	/* Parse command line options */
	opt = 0;
	while((c = getopt(argc, argv, "s:")) != -1)
	{
		switch(c)
		{
		case 's':
			opt |= OPT_s_baud;
			baud_str = optarg;
			break;
		default:
			break;
		}
	}
	
	argv += optind;

	if(!*argv)
	{
		usage();
		exit(EXIT_FAILURE);
	}

	/* We want to know if the baud rate is valid before we start touching the ttys */
	if(opt & OPT_s_baud)
	{
		int tty_value = atoi(baud_str);
		if(tty_value < 0)
		{
			fprintf(stderr,"Invalid baud rate: %s\n",baud_str);
			exit(EXIT_FAILURE);
		}
		baud_code = tty_value_to_baud(tty_value);
		if (baud_code < 0)
		{
			fprintf(stderr,"Invalid baud rate: %s\n",baud_str);
			exit(EXIT_FAILURE);
		}
	}

	/* Trap signals in order to restore tty states upon exit */
	signal(SIGHUP,sig_handler);
	signal(SIGINT,sig_handler);
	signal(SIGQUIT,sig_handler);
	signal(SIGTERM,sig_handler);

	/* Open tty */
	handle = open(*argv, O_RDWR | O_NDELAY);
	if(handle < 0)
	{
		char *buf = malloc(strlen(*argv) + 5);
		strcpy(buf,"/dev/");
		strcat(buf,*argv);
		handle = open(buf, O_RDWR | O_NDELAY);
		free(buf);
		if(handle < 0)
		{
			fprintf(stderr,"Failed to open tty\n");
			exit(EXIT_FAILURE);
		}
	}

	/* Save current tty state */
	save_state();

	/* Configure tty */
	memcpy(&state, &saved_state, sizeof(state));
	
	memset(&state.c_cc, 0, sizeof(state.c_cc));
	state.c_cc[VMIN] = 1;
	state.c_iflag = IGNBRK | IGNPAR;
	state.c_oflag = 0;
	state.c_lflag = 0;
	state.c_cflag = CS8 | HUPCL | CREAD | CLOCAL;
	cfsetispeed(&state, cfgetispeed(&saved_state));
	cfsetospeed(&state, cfgetospeed(&saved_state));

	if(opt & OPT_s_baud)
	{
		cfsetispeed(&state, baud_code);
		cfsetospeed(&state, baud_code);
	}

	set_state(&state);

    /* daemonize */
    pid = fork();

    if(pid < 0)
    {
        return 1;
    }
    if(pid > 0)
    {
        return 0;
    }

    umask(0);

    sid = setsid();
    if(sid < 0)
    {
        return 1;
    }

	/* Watch line for hangup */
	while(ioctl(handle, TIOCMGET, &i) >= 0 && !(i & TIOCM_CAR))
	{
		sleep(15);
	}

	return EXIT_SUCCESS;
}

