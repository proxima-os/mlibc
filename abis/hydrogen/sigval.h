/* IWYU pragma: private, include <signal.h> */
#ifndef _ABIBITS_SIGVAL_H
#define _ABIBITS_SIGVAL_H

#include <hydrogen/signal.h>

#ifdef __cplusplus
extern "C" {
#endif

union sigval {
	union __sigval __base;
};

#define sival_int __base.__int
#define sival_ptr __base.__ptr

#ifdef __cplusplus
}
#endif

#endif /* _ABIBITS_SIGVAL_H */
