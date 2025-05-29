/* IWYU pragma: private, include <signal.h> */
#ifndef _ABIBITS_SIGNAL_H
#define _ABIBITS_SIGNAL_H

#include <abi-bits/pid_t.h>
#include <abi-bits/sigevent.h>
#include <abi-bits/uid_t.h>
#include <bits/size_t.h>
#include <hydrogen/signal.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*__sighandler)(int);

#define SIG_ERR ((__sighandler)-1)
#define SIG_DFL __SIG_DFL
#define SIG_IGN __SIG_IGN

#define SIGHUP __SIGHUP
#define SIGINT __SIGINT
#define SIGQUIT __SIGQUIT
#define SIGILL __SIGILL
#define SIGTRAP __SIGTRAP
#define SIGABRT __SIGABRT
#define SIGBUS __SIGBUS
#define SIGFPE __SIGFPE
#define SIGKILL __SIGKILL
#define SIGUSR1 __SIGUSR1
#define SIGSEGV __SIGSEGV
#define SIGUSR2 __SIGUSR2
#define SIGPIPE __SIGPIPE
#define SIGALRM __SIGALRM
#define SIGTERM __SIGTERM
#define SIGCHLD __SIGCHLD
#define SIGCONT __SIGCONT
#define SIGSTOP __SIGSTOP
#define SIGTSTP __SIGTSTP
#define SIGTTIN __SIGTTIN
#define SIGTTOU __SIGTTOU
#define SIGURG __SIGURG
#define SIGXCPU __SIGXCPU
#define SIGXFSZ __SIGXFSZ
#define SIGVTALRM __SIGVTALRM
#define SIGPROF __SIGPROF
#define SIGWINCH __SIGWINCH
#define SIGIO __SIGIO
#define SIGPWR __SIGPWR
#define SIGSYS __SIGSYS
#define SIGCANCEL __SIGRTMIN
#define SIGRTMIN (__SIGRTMIN + 3)
#define SIGRTMAX __SIGRTMAX
#define NSIG __NSIG

typedef __sigset_t sigset_t;

typedef __siginfo_t siginfo_t;

#define si_signo __signo
#define si_code __code
#define si_errno __errno
#define si_pid __data.__user_or_sigchld.__pid
#define si_uid __data.__user_or_sigchld.__uid
#define si_status __data.__user_or_sigchld.__status
#define si_value __data.__queue.__value
#define si_addr __data.__sigsegv.__address
#define si_ptr si_value.sival_ptr
#define si_int si_value.sival_int

#define SI_USER __SI_USER
#define SI_QUEUE __SI_QUEUE
#define SI_TIMER __SI_TIMER
#define SI_ASYNCIO __SI_ASYNCIO
#define SI_MESGQ __SI_MESGQ
#define SI_TKILL __SI_TKILL

#define ILL_ILLOPC __ILL_ILLOPC
#define ILL_ILLOPN __ILL_ILLOPN
#define ILL_ILLADR __ILL_ILLADR
#define ILL_ILLTRP __ILL_ILLTRP
#define ILL_PRVOPC __ILL_PRVOPC
#define ILL_PRVREG __ILL_PRVREG
#define ILL_COPROC __ILL_COPROC
#define ILL_BADSTK __ILL_BADSTK

#define SEGV_MAPERR __SEGV_MAPERR
#define SEGV_ACCERR __SEGV_ACCERR

#define BUS_ADRALN __BUS_ADRALN
#define BUS_ADRERR __BUS_ADRERR
#define BUS_OBJERR __BUS_OBJERR

struct sigaction {
	struct __sigaction __base;
};

#define sa_handler __base.__func.__handler
#define sa_sigaction __base.__func.__action
#define sa_mask __base.__mask
#define sa_flags __base.__flags

#define SA_NOCLDSTOP __SA_NOCLDSTOP
#define SA_ONSTACK __SA_ONSTACK
#define SA_RESETHAND __SA_RESETHAND
#define SA_RESTART __SA_RESTART
#define SA_SIGINFO __SA_SIGINFO
#define SA_NOCLDWAIT __SA_NOCLDWAIT
#define SA_NODEFER __SA_NODEFER

#define SIG_BLOCK __SIG_BLOCK
#define SIG_UNBLOCK __SIG_UNBLOCK
#define SIG_SETMASK __SIG_SETMASK

typedef __stack_t stack_t;

#define ss_sp __pointer
#define ss_size __size
#define ss_flags __flags

#define SS_ONSTACK __SS_ONSTACK
#define SS_DISABLE __SS_DISABLE

#define MINSIGSTKSZ __MINSIGSTKSZ
#define SIGSTKSZ __SIGSTKSZ

typedef __mcontext_t mcontext_t;
typedef __ucontext_t ucontext_t;

#ifdef __cplusplus
}
#endif

#endif /* _ABIBITS_SIGNAL_H */
