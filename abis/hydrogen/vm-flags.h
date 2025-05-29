/* IWYU pragma: private, include <sys/mman.h> */
#ifndef _ABIBITS_VM_FLAGS_H
#define _ABIBITS_VM_FLAGS_H

#define MAP_FAILED ((void *)(-1))

#define PROT_READ (1 << 0)
#define PROT_WRITE (1 << 1)
#define PROT_EXEC (1 << 2)
#define MAP_FIXED (3 << 3)
#define MAP_SHARED (1 << 6)

#define PROT_NONE 0
#define MAP_FILE 0
#define MAP_PRIVATE 0
#define MAP_ANONYMOUS (1 << 30)

#define MAP_ANON MAP_ANONYMOUS

#endif /* _ABIBITS_VM_FLAGS_H */
