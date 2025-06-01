/* IWYU pragma: private, include <fcntl.h> */
#ifndef _ABIBITS_FCNTL_H
#define _ABIBITS_FCNTL_H

#include <hydrogen/fcntl.h>

#define O_RDONLY __O_RDONLY
#define O_WRONLY __O_WRONLY
#define O_CLOFORK __O_CLOFORK
#define O_CREAT __O_CREAT
#define O_DIRECTORY __O_DIRECTORY
#define O_EXCL __O_EXCL
#define O_NOFOLLOW __O_NOFOLLOW
#define O_TRUNC __O_TRUNC
#define O_APPEND __O_APPEND
#define O_CLOEXEC __O_CLOEXEC
#define O_NONBLOCK __O_NONBLOCK
#define O_TMPFILE __O_TMPFILE
#define O_NOCTTY 0

#define O_RDWR (O_RDONLY | O_WRONLY)
#define O_ACCMODE O_RDWR

#define F_DUPFD 0
#define F_GETFD 1
#define F_SETFD 2
#define F_GETFL 3
#define F_SETFL 4
#define F_GETLK 5
#define F_SETLK 6
#define F_SETLKW 7

#define F_RDLCK 0
#define F_WRLCK 1
#define F_UNLCK 2

#define FD_CLOEXEC (1 << 0)
#define FD_CLOFORK (1 << 1)

#define AT_FDCWD (-1)

#define AT_SYMLINK_FOLLOW __AT_SYMLINK_FOLLOW
#define AT_REMOVEDIR __AT_REMOVEDIR
#define AT_EACCESS __AT_EACCESS
#define AT_SYMLINK_NOFOLLOW __AT_SYMLINK_NOFOLLOW
#define AT_EMPTY_PATH (1 << 30)

#define POSIX_FADV_NORMAL 0
#define POSIX_FADV_RANDOM 1
#define POSIX_FADV_SEQUENTIAL 2
#define POSIX_FADV_WILLNEED 3
#define POSIX_FADV_DONTNEED 4
#define POSIX_FADV_NOREUSE 5

#endif /* _ABIBITS_FCNTL_H */
