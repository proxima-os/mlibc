/* IWYU pragma: private, include <termios.h> */
#ifndef _ABIBITS_TERMIOS_H
#define _ABIBITS_TERMIOS_H

#include <hydrogen/termios.h>

typedef __cc_t cc_t;
typedef unsigned speed_t;
typedef __tcflag_t tcflag_t;

/* indices for the c_cc array in struct termios */
#define NCCS __NCCS
/*#define VINTR    1
#define VQUIT    2
#define VERASE   3
#define VKILL    4
#define VEOF     5*/
#define VTIME 6
#define VMIN 7
/*#define VSWTC    8
#define VSTART   9
#define VSTOP    10
#define VSUSP    11
#define VEOL     12
#define VREPRINT 13
#define VDISCARD 14
#define VWERASE  15
#define VLNEXT   16
#define VEOL2    17*/

/* bitwise flags for c_iflag in struct termios */
#define IUTF8 __IUTF8
#define BRKINT 0
#define ICRNL 0
#define IGNBRK 0
#define IGNCR 0
/*#define IGNPAR 0*/
#define INLCR 0
/*#define INPCK 0*/
#define ISTRIP 0
/*#define IXANY 0
#define IXOFF 0*/
#define IXON 0
#define PARMRK 0

/* bitwise flags for c_oflag in struct termios */
#define OPOST __OPOST
#define ONLCR __ONLCR
#define OCRNL __OCRNL
#define ONOCR __ONOCR
#define ONLRET __ONLRET
#define OFILL __OFILL
#define OFDEL __OFDEL

#if defined(_GNU_SOURCE) || defined(_BSD_SOURCE) || defined(_XOPEN_SOURCE)

#define NLDLY __NLDLY
#define NL0 __NL0
#define NL1 __NL1

#define CRDLY __CRDLY
#define CR0 __CR0
#define CR1 __CR1
#define CR2 __CR2
#define CR3 __CR3

#define TABDLY __TABDLY
#define TAB0 __TAB0
#define TAB1 __TAB1
#define TAB2 __TAB2
#define TAB3 __TAB3

#define BSDLY __BSDLY
#define BS0 __BS0
#define BS1 __BS1

#define FFDLY __FFDLY
#define FF0 __FR0
#define FF1 __FR1

#endif

#define VTDLY __VTDLY
#define VT0 __VT0
#define VT1 __VT1

/* bitwise constants for c_cflag in struct termios */
#define CSIZE 0
/*#define CS5 0
#define CS6 0
#define CS7 0*/
#define CS8 0

/*#define CSTOPB 0
#define CREAD 0*/
#define PARENB 0
/*#define PARODD 0
#define HUPCL 0
#define CLOCAL 0*/

/* bitwise constants for c_lflag in struct termios */
#define ISIG 0
#define ICANON 0
#define ECHO 0
/*#define ECHOE 0
#define ECHOK 0*/
#define ECHONL 0
/*#define NOFLSH 0
#define TOSTOP 0*/
#define IEXTEN 0

#if defined(_GNU_SOURCE) || defined(_BSD_SOURCE)

/*#define EXTA    0
#define EXTB    0*/
#define CBAUD   0
/*#define CBAUDEX 0
#define CIBAUD  0
#define CMSPAR  0
#define CRTSCTS 0*/

/*#define XCASE   0
#define ECHOCTL 0
#define ECHOPRT 0
#define ECHOKE  0
#define FLUSHO  0
#define PENDIN  0
#define EXTPROC 0*/

/*#define XTABS 0*/

#endif

struct termios {
	struct __termios __base;
	unsigned char c_line;
	speed_t ibaud;
	speed_t obaud;
};

#define NCC 8
struct termio {
	struct {
		unsigned short __input_flags;
		unsigned short __output_flags;
		unsigned short __control_flags;
		unsigned short __local_flags;
		unsigned char __control_chars[NCC];
	} __base;
	unsigned char c_line;
};

#define c_iflag __base.__input_flags
#define c_oflag __base.__output_flags
#define c_cflag __base.__control_flags
#define c_lflag __base.__local_flags
#define c_cc __base.__control_chars

#endif
