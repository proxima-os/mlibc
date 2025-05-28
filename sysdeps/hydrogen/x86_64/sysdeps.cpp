#include <hydrogen/x86_64/segments.h>
#include <mlibc/all-sysdeps.hpp>

namespace mlibc {
int sys_tcb_set(void *pointer) { return hydrogen_x86_64_set_fs_base((uintptr_t)pointer); }

const char *hydrogen_machine_name() { return "x86_64"; }
} // namespace mlibc
