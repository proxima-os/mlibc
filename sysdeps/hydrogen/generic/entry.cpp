#include <mlibc/elf/startup.h>
#include <stdint.h>
#include <stdlib.h>

extern "C" void __dlapi_enter(uintptr_t *);

extern "C" void __mlibc_entry(uintptr_t *entry_stack, int (*main)(int, char **, char **)) {
	__dlapi_enter(entry_stack);
	exit(main(mlibc::entry_stack.argc, mlibc::entry_stack.argv, mlibc::entry_stack.envp));
}
