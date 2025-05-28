#ifndef _ABIBITS_STAT_H
#define _ABIBITS_STAT_H

#include <abi-bits/blkcnt_t.h>
#include <abi-bits/blksize_t.h>
#include <abi-bits/dev_t.h>
#include <abi-bits/gid_t.h>
#include <abi-bits/ino_t.h>
#include <abi-bits/mode_t.h>
#include <abi-bits/nlink_t.h>
#include <abi-bits/uid_t.h>
#include <bits/ansi/time_t.h>
#include <bits/ansi/timespec.h>
#include <bits/off_t.h>
#include <hydrogen/stat.h>

#ifdef __cplusplus
extern "C" {
#endif

#define S_IXOTH __S_IXOTH
#define S_IWOTH __S_IWOTH
#define S_IROTH __S_IROTH
#define S_IXGRP __S_IXGRP
#define S_IWGRP __S_IWGRP
#define S_IRGRP __S_IRGRP
#define S_IXUSR __S_IXUSR
#define S_IWUSR __S_IWUSR
#define S_IRUSR __S_IRUSR
#define S_ISVTX __S_ISVTX
#define S_ISGID __S_ISGID
#define S_ISUID __S_ISUID

#define S_IRWXO (S_IROTH | S_IWOTH | S_IXOTH)
#define S_IRWXG (S_IRGRP | S_IWGRP | S_IXGRP)
#define S_IRWXU (S_IRUSR | S_IWUSR | S_IXUSR)

#define S_IFMT 0xf000
#define S_IFREG 0x8000
#define S_IFDIR 0x4000
#define S_IFLNK 0xa000
#define S_IFCHR 0x2000
#define S_IFBLK 0x6000
#define S_IFIFO 0x1000
#define S_IFSOCK 0xc000

struct stat {
	dev_t st_dev;
	ino_t st_ino;
	nlink_t st_nlink;
	blkcnt_t st_blocks;
	off_t st_size;
	blksize_t st_blksize;
	struct timespec st_atim;
	struct timespec __unused1;
	struct timespec st_ctim;
	struct timespec st_mtim;
	int __unused2;
	mode_t st_mode;
	uid_t st_uid;
	gid_t st_gid;
};

#define stat64 stat

#ifdef __cplusplus
}
#endif

#endif /* _ABIBITS_STAT_H */
