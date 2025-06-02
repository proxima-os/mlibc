/* IWYU pragma: private, include <termios.h> */
#ifndef _ABIBITS_TERMIOS_H
#define _ABIBITS_TERMIOS_H

#include <hydrogen/termios.h>

typedef __cc_t cc_t;
typedef __speed_t speed_t;
typedef __tcflag_t tcflag_t;

/* indices for the c_cc array in struct termios */
#define NCCS __NCCS
#define VINTR __VINTR
#define VQUIT __VQUIT
#define VERASE __VERASE
#define VKILL __VKILL
#define VEOF __VEOF
#define VTIME __VTIME
#define VMIN __VMIN
#define VSTART __VSTART
#define VSTOP __VSTOP
#define VSUSP __VSUSP
#define VEOL __VEOL

/* bitwise flags for c_iflag in struct termios */
#define IUTF8 __IUTF8
#define BRKINT __BRKINT
#define ICRNL __ICRNL
#define IGNBRK __IGNBRK
#define IGNCR __IGNCR
#define IGNPAR __IGNPAR
#define INLCR __INLCR
#define INPCK __INPCK
#define ISTRIP __ISTRIP
#define IXANY __IXANY
#define IXOFF __IXOFF
#define IXON __IXON
#define PARMRK __PARMRK
#define IMAXBEL __IMAXBEL

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
#define FF0 __FF0
#define FF1 __FF1

#endif

#define VTDLY __VTDLY
#define VT0 __VT0
#define VT1 __VT1

/* bitwise constants for c_cflag in struct termios */
#define CSIZE __CSIZE
#define CS5 __CS5
#define CS6 __CS6
#define CS7 __CS7
#define CS8 __CS8

#define CSTOPB __CSTOPB
#define CREAD __CREAD
#define PARENB __PARENB
#define PARODD __PARODD
#define HUPCL __HUPCL
#define CLOCAL __CLOCAL

/* bitwise constants for c_lflag in struct termios */
#define ISIG __ISIG
#define ICANON __ICANON
#define ECHO __ECHO
#define ECHOE __ECHOE
#define ECHOK __ECHOK
#define ECHONL __ECHONL
#define NOFLSH __NOFLSH
#define TOSTOP __TOSTOP
#define IEXTEN __IEXTEN

#if defined(_GNU_SOURCE) || defined(_BSD_SOURCE)

#define XTABS TAB3

#define CBAUD (0x100f << 20)

/*#define EXTA    0
#define EXTB    0
#define CBAUDEX 0
#define CIBAUD  0
#define CMSPAR  0
#define CRTSCTS 0*/

#define ECHOKE __ECHOKE
#define ECHOCTL __ECHOCTL

/*#define XCASE   0
#define ECHOPRT 0
#define FLUSHO  0
#define PENDIN  0
#define EXTPROC 0*/

#endif

struct termios {
	struct __termios __base;
	unsigned char c_line;
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
#define ibaud __base.__input_speed
#define obaud __base.__output_speed

#endif
