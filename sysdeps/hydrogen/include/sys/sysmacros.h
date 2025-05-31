#ifndef _SYS_SYSMACROS_H
#define _SYS_SYSMACROS_H

#ifdef __cplusplus
extern "C" {
#endif

static unsigned int __mlibc_dev_major(unsigned long long int __dev) { return __dev >> 32; }

static unsigned int __mlibc_dev_minor(unsigned long long int __dev) { return __dev & 0xffffffff; }

static unsigned long long int __mlibc_dev_makedev(unsigned int __major, unsigned int __minor) {
	return ((unsigned long long int)__major << 32) | __minor;
}

#define major(dev) __mlibc_dev_major(dev)
#define minor(dev) __mlibc_dev_minor(dev)
#define makedev(major, minor) __mlibc_dev_makedev(major, minor)

#ifdef __cplusplus
}
#endif

#endif /* _SYS_SYSMACROS_H */
