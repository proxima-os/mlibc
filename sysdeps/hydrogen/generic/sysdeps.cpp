#include <bits/ensure.h>
#include <dirent.h>
#include <errno.h>
#include <hydrogen/eventqueue.h>
#include <hydrogen/filesystem.h>
#include <hydrogen/handle.h>
#include <hydrogen/hydrogen.h>
#include <hydrogen/ioctl-data.h>
#include <hydrogen/ioctl.h>
#include <hydrogen/memory.h>
#include <hydrogen/process.h>
#include <hydrogen/thread.h>
#include <hydrogen/time.h>
#include <hydrogen/types.h>
#include <limits.h>
#include <mlibc/all-sysdeps.hpp>
#include <stdio.h>
#include <string.h>
#include <termios.h>

namespace mlibc {
void sys_libc_log(const char *message) {
	hydrogen_fs_write(STDERR_FILENO, message, strlen(message));
	hydrogen_fs_write(STDERR_FILENO, "\n", 1);
}

void sys_libc_panic() {
	hydrogen_thread_send_signal(HYDROGEN_THIS_THREAD, SIGABRT);
	__builtin_trap();
}

int sys_anon_allocate(size_t size, void **pointer) {
	hydrogen_ret_t ret = hydrogen_vmm_map(
	    HYDROGEN_THIS_VMM,
	    0,
	    size,
	    HYDROGEN_MEM_READ | HYDROGEN_MEM_WRITE,
	    HYDROGEN_INVALID_HANDLE,
	    0
	);

	if (ret.error == 0) {
		*pointer = ret.pointer;
	}

	return ret.error;
}

int sys_anon_free(void *pointer, size_t size) {
	return hydrogen_vmm_unmap(HYDROGEN_THIS_VMM, (uintptr_t)pointer, size);
}

static __int128_t createTime(struct timespec time) {
	return (__int128_t)time.tv_sec * 1'000'000'000ll + time.tv_nsec;
}

static uint64_t createTimeU64(struct timespec time) {
	return time.tv_sec * 1'000'000'000ull + time.tv_nsec;
}

int sys_futex_wait(int *pointer, int expected, const struct timespec *time) {
	uint64_t deadline;

	if (time) {
		deadline = hydrogen_boot_time() + createTimeU64(*time);
	} else {
		deadline = 0;
	}

	return hydrogen_memory_wait(reinterpret_cast<uint32_t *>(pointer), expected, deadline);
}

int sys_futex_wake(int *pointer) { return hydrogen_memory_wake((uint32_t *)pointer, 0).error; }

int sys_open(const char *pathname, int flags, mode_t mode, int *fd) {
	return sys_openat(AT_FDCWD, pathname, flags, mode, fd);
}

int sys_openat(int dirfd, const char *path, int flags, mode_t mode, int *fd) {
	if ((flags & O_ACCMODE) == 0) {
		return EINVAL;
	}

	if (dirfd == AT_FDCWD) {
		dirfd = HYDROGEN_INVALID_HANDLE;
	}

	hydrogen_ret_t ret = hydrogen_fs_open(dirfd, path, strlen(path), flags, mode);

	if (ret.error == 0) {
		*fd = ret.integer;
	}

	return ret.error;
}

int sys_close(int fd) { return hydrogen_namespace_remove(HYDROGEN_THIS_NAMESPACE, fd); }

int sys_seek(int fd, off_t offset, int whence, off_t *new_offset) {
	hydrogen_seek_anchor_t anchor;

	switch (whence) {
		case SEEK_SET:
			anchor = HYDROGEN_SEEK_BEGIN;
			break;
		case SEEK_CUR:
			anchor = HYDROGEN_SEEK_CURRENT;
			break;
		case SEEK_END:
			anchor = HYDROGEN_SEEK_END;
			break;
		default:
			return EINVAL;
	}

	hydrogen_ret_t ret = hydrogen_fs_seek(fd, anchor, offset);

	if (ret.error == 0) {
		*new_offset = ret.integer;
	}

	return ret.error;
}

int sys_read(int fd, void *buf, size_t count, ssize_t *bytes_read) {
	if (count > SSIZE_MAX) {
		count = SSIZE_MAX;
	}

	hydrogen_ret_t ret = hydrogen_fs_read(fd, buf, count);

	if (ret.error == 0) {
		*bytes_read = ret.integer;
	}

	return ret.error;
}

int sys_write(int fd, const void *buf, size_t count, ssize_t *bytes_read) {
	if (count > SSIZE_MAX) {
		count = SSIZE_MAX;
	}

	hydrogen_ret_t ret = hydrogen_fs_write(fd, buf, count);

	if (ret.error == 0) {
		*bytes_read = ret.integer;
	}

	return ret.error;
}

int sys_vm_map(void *hint, size_t size, int prot, int flags, int fd, off_t offset, void **window) {
	uint32_t real_flags = 0;

	if ((prot & PROT_READ) == PROT_READ) {
		real_flags |= HYDROGEN_MEM_READ;
	}

	if ((prot & PROT_WRITE) == PROT_WRITE) {
		real_flags |= HYDROGEN_MEM_WRITE;
	}

	if ((prot & PROT_EXEC) == PROT_EXEC) {
		real_flags |= HYDROGEN_MEM_EXEC;
	}

	if ((flags & MAP_FIXED) == MAP_FIXED) {
		real_flags |= HYDROGEN_MEM_EXACT | HYDROGEN_MEM_OVERWRITE;
	}

	if ((flags & MAP_SHARED) == MAP_SHARED) {
		real_flags |= HYDROGEN_MEM_SHARED;
	}

	hydrogen_ret_t ret;

	if ((flags & MAP_ANONYMOUS) == MAP_ANONYMOUS) {
		int object = HYDROGEN_INVALID_HANDLE;

		if ((flags & MAP_SHARED) == MAP_SHARED) {
			ret = hydrogen_mem_object_create(size, 0);

			if (ret.error) {
				return ret.error;
			}

			object = ret.integer;
		}

		ret = hydrogen_vmm_map(HYDROGEN_THIS_VMM, (uintptr_t)hint, size, real_flags, object, 0);

		if (object != HYDROGEN_INVALID_HANDLE) {
			hydrogen_namespace_remove(HYDROGEN_THIS_NAMESPACE, object);
		}
	} else {
		ret = hydrogen_fs_mmap(fd, HYDROGEN_THIS_VMM, (uintptr_t)hint, size, real_flags, offset);
	}

	if (ret.error == 0) {
		*window = ret.pointer;
	}

	return ret.error;
}

int sys_vm_protect(void *pointer, size_t size, int prot) {
	uint32_t real_flags = 0;

	if ((prot & PROT_READ) == PROT_READ) {
		real_flags |= HYDROGEN_MEM_READ;
	}

	if ((prot & PROT_WRITE) == PROT_WRITE) {
		real_flags |= HYDROGEN_MEM_WRITE;
	}

	if ((prot & PROT_EXEC) == PROT_EXEC) {
		real_flags |= HYDROGEN_MEM_EXEC;
	}

	return hydrogen_vmm_remap(HYDROGEN_THIS_VMM, (uintptr_t)pointer, size, real_flags);
}

int sys_vm_unmap(void *pointer, size_t size) {
	return hydrogen_vmm_unmap(HYDROGEN_THIS_VMM, (uintptr_t)pointer, size);
}

void sys_exit(int status) { hydrogen_process_exit(status); }

int sys_clock_get(int clock, time_t *secs, long *nanos) {
	__int128_t time;

	switch (clock) {
		case CLOCK_REALTIME:
		case CLOCK_REALTIME_COARSE:
		case CLOCK_REALTIME_ALARM:
			time = hydrogen_get_real_time();
			break;
		case CLOCK_MONOTONIC:
		case CLOCK_MONOTONIC_RAW:
		case CLOCK_MONOTONIC_COARSE:
		case CLOCK_BOOTTIME:
		case CLOCK_BOOTTIME_ALARM:
			time = hydrogen_boot_time();
			break;
		case CLOCK_PROCESS_CPUTIME_ID: {
			hydrogen_process_cpu_time_t data;
			int error = hydrogen_process_get_cpu_time(&data);
			if (error != 0) {
				return error;
			}
			time = data.self.kernel + data.self.user;
			break;
		}
		case CLOCK_THREAD_CPUTIME_ID: {
			hydrogen_cpu_time_t data;
			int error = hydrogen_thread_get_cpu_time(&data);
			if (error != 0) {
				return error;
			}
			time = data.kernel + data.user;
			break;
		}
		default:
			return EINVAL;
	}

	*secs = time / 1'000'000'000;
	*nanos = time % 1'000'000'000;

	return 0;
}

void sys_thread_exit() { hydrogen_thread_exit(0); }

int sys_prepare_stack(
    void **stack,
    void *entry,
    void *user_arg,
    void *tcb,
    size_t *stack_size,
    size_t *guard_size,
    void **stack_base
) {
	if (*stack_size == 0) {
		*stack_size = 0x200000;
	}

	if (*stack) {
		*stack_base = *stack;
		*guard_size = 0;
	} else {
		hydrogen_ret_t ret = hydrogen_vmm_map(
		    HYDROGEN_THIS_VMM,
		    0,
		    *stack_size + *guard_size,
		    HYDROGEN_MEM_LAZY_RESERVE,
		    HYDROGEN_INVALID_HANDLE,
		    0
		);

		if (ret.error) {
			return ret.error;
		}

		int error = hydrogen_vmm_remap(
		    HYDROGEN_THIS_VMM,
		    ret.integer + *guard_size,
		    *stack_size,
		    HYDROGEN_MEM_READ | HYDROGEN_MEM_WRITE
		);

		if (error) {
			hydrogen_vmm_unmap(HYDROGEN_THIS_VMM, ret.integer, *stack_size + *guard_size);
			return error;
		}

		*stack_base = reinterpret_cast<void *>(ret.integer + *guard_size);
	}

	auto sp = reinterpret_cast<void **>(reinterpret_cast<char *>(*stack_base) + *stack_size);
	*--sp = tcb;
	*--sp = user_arg;
	*--sp = entry;
	*stack = reinterpret_cast<void *>(sp);
	return 0;
}

extern "C" void __mlibc_hydrogen_thread_entry();

extern "C" [[noreturn, gnu::visibility("hidden")]] void
__mlibc_hydrogen_thread_start(void (*entry)(void *), void *user_arg, void *tcb) {
	__ensure(!sys_tcb_set(tcb));
	entry(user_arg);
	sys_thread_exit();
}

int sys_clone(void *, pid_t *pid_out, void *stack) {
	hydrogen_ret_t ret = hydrogen_thread_create(
	    HYDROGEN_THIS_PROCESS,
	    HYDROGEN_THIS_VMM,
	    HYDROGEN_THIS_NAMESPACE,
	    reinterpret_cast<uintptr_t>(__mlibc_hydrogen_thread_entry),
	    reinterpret_cast<uintptr_t>(stack),
	    0
	);

	if (ret.error == 0) {
		*pid_out = hydrogen_thread_get_id(ret.integer).integer;
		hydrogen_namespace_remove(HYDROGEN_THIS_NAMESPACE, ret.integer);
	}

	return ret.error;
}

int sys_open_dir(const char *path, int *handle) {
	return sys_open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC, 0, handle);
}

int sys_read_entries(int handle, void *buffer, size_t max_size, size_t *bytes_read) {
	hydrogen_ret_t ret = hydrogen_fs_readdir(handle, buffer, max_size);

	if (ret.error == 0) {
		*bytes_read = ret.integer;
	}

	return ret.error;
}

int sys_pread(int fd, void *buf, size_t n, off_t off, ssize_t *bytes_read) {
	if (n > SSIZE_MAX) {
		n = SSIZE_MAX;
	}

	hydrogen_ret_t ret = hydrogen_fs_pread(fd, buf, n, off);

	if (ret.error == 0) {
		*bytes_read = ret.integer;
	}

	return ret.error;
}

int sys_clock_set(int clock, time_t secs, long nanos) {
	switch (clock) {
		case CLOCK_REALTIME:
			return hydrogen_set_real_time(createTimeU64({secs, nanos}));
		default:
			return EINVAL;
	}
}

int sys_clock_getres(int clock, time_t *secs, long *nanos) {
	switch (clock) {
		case CLOCK_REALTIME:
		case CLOCK_REALTIME_ALARM:
		case CLOCK_REALTIME_COARSE:
		case CLOCK_MONOTONIC:
		case CLOCK_MONOTONIC_COARSE:
		case CLOCK_MONOTONIC_RAW:
		case CLOCK_BOOTTIME:
		case CLOCK_BOOTTIME_ALARM:
			*secs = 0;
			*nanos = 1;
			return 0;
		default:
			return EINVAL;
	}
}

static struct timespec createTimeSpec(__int128_t time) {
	if (time >= 0) {
		return {(time_t)(time / 1'000'000'000), (long)(time % 1'000'000'000)};
	} else {
		auto seconds = (time - 999'999'999) / 1'000'000'000;
		return {(time_t)seconds, (long)(time - time * 1'000'000'000)};
	}
}

int sys_sleep(time_t *secs, long *nanos) {
	uint64_t deadline = hydrogen_boot_time() + createTime({*secs, *nanos});
	int error = hydrogen_thread_sleep(deadline);

	if (!error) {
		return 0;
	}

	uint64_t current = hydrogen_boot_time();

	if (current < deadline) {
		struct timespec spec = createTimeSpec(deadline - current);
		*secs = spec.tv_sec;
		*nanos = spec.tv_nsec;
	} else {
		*secs = 0;
		*nanos = 0;
	}

	return error;
}

int sys_rmdir(const char *path) { return sys_unlinkat(AT_FDCWD, path, AT_REMOVEDIR); }

int sys_unlinkat(int dirfd, const char *path, int flags) {
	if (dirfd == AT_FDCWD) {
		dirfd = HYDROGEN_INVALID_HANDLE;
	}

	return hydrogen_fs_unlink(dirfd, path, strlen(path), flags);
}

int sys_rename(const char *path, const char *new_path) {
	return sys_renameat(AT_FDCWD, path, AT_FDCWD, new_path);
}

int sys_renameat(int olddirfd, const char *old_path, int newdirfd, const char *new_path) {
	if (olddirfd == AT_FDCWD) {
		olddirfd = HYDROGEN_INVALID_HANDLE;
	}

	if (newdirfd == AT_FDCWD) {
		newdirfd = HYDROGEN_INVALID_HANDLE;
	}

	return hydrogen_fs_rename(
	    olddirfd, old_path, strlen(old_path), newdirfd, new_path, strlen(new_path)
	);
}

static sigset_t mlibcSigsetToKernel(sigset_t set) {
	return set << 1; // in mlibc, bit 0 of a sigset is for signal 1
}

static sigset_t kernelSigsetToMlibc(sigset_t set) {
	return set >> 1; // in the kernel, bit 0 of a sigset is for signal 0
}

int sys_sigprocmask(int how, const sigset_t *__restrict set, sigset_t *__restrict retrieve) {
	sigset_t src, dst;

	if (set) {
		src = mlibcSigsetToKernel(*set);
	}

	int error = hydrogen_thread_sigmask(how, set ? &src : NULL, retrieve ? &dst : NULL);

	if (error == 0) {
		if (retrieve) {
			*retrieve = kernelSigsetToMlibc(dst);
		}
	}

	return error;
}

int sys_sigaction(
    int sig, const struct sigaction *__restrict action, struct sigaction *__restrict old
) {
	return hydrogen_process_sigaction(HYDROGEN_THIS_PROCESS, sig, &action->__base, &old->__base);
}

int sys_fork(pid_t *child) {
	hydrogen_ret_t ns = hydrogen_namespace_clone(HYDROGEN_THIS_NAMESPACE, 0);

	if (ns.error) {
		return ns.error;
	}

	hydrogen_ret_t proc = hydrogen_process_create(0);

	if (proc.error) {
		hydrogen_namespace_remove(HYDROGEN_THIS_NAMESPACE, ns.integer);
		return proc.error;
	}

	hydrogen_ret_t thread = hydrogen_thread_clone(proc.integer, HYDROGEN_CLONED_VMM, ns.integer, 0);

	if (thread.error == 0) {
		if (thread.integer == (size_t)HYDROGEN_INVALID_HANDLE) {
			// We're in the child, whose namespace was cloned before any of the handles were
			// created, so we don't need to close anything.
			*child = 0;
			return 0;
		}

		hydrogen_namespace_remove(HYDROGEN_THIS_NAMESPACE, thread.integer);
		*child = hydrogen_process_getpid(proc.integer).integer;
	}

	hydrogen_namespace_remove(HYDROGEN_THIS_NAMESPACE, proc.integer);
	hydrogen_namespace_remove(HYDROGEN_THIS_NAMESPACE, ns.integer);
	return 0;
}

int sys_waitpid(pid_t pid, int *status, int flags, struct rusage *ru, pid_t *ret_pid) {
	if (ru) {
		return ENOSYS;
	}

	unsigned real_flags = HYDROGEN_PROCESS_WAIT_EXITED | HYDROGEN_PROCESS_WAIT_KILLED
	                      | HYDROGEN_PROCESS_WAIT_DISCARD | HYDROGEN_PROCESS_WAIT_UNQUEUE;
	uint64_t deadline = 0;

	if ((flags & WNOHANG) == WNOHANG) {
		deadline = 1;
	}

	if ((flags & WUNTRACED) == WUNTRACED) {
		real_flags |= HYDROGEN_PROCESS_WAIT_STOPPED;
	}

	if ((flags & WCONTINUED) == WCONTINUED) {
		real_flags |= HYDROGEN_PROCESS_WAIT_CONTINUED;
	}

	hydrogen_ret_t ret;
	siginfo_t info;

	if (pid < -1) {
		ret = hydrogen_process_wait_id(-pid, real_flags, &info, deadline);
	} else if (pid == -1) {
		ret = hydrogen_process_wait_id(0, real_flags, &info, deadline);
	} else if (pid == 0) {
		ret = hydrogen_process_wait_id(
		    hydrogen_process_getpgid(HYDROGEN_THIS_PROCESS).integer, real_flags, &info, deadline
		);
	} else {
		hydrogen_ret_t proc = hydrogen_process_find(pid, 0);

		if (proc.error) {
			return proc.error;
		}

		ret.error = hydrogen_process_wait(proc.integer, real_flags, &info, deadline);

		if (ret.error == 0) {
			ret.integer = hydrogen_process_getpid(proc.integer).integer;
		}

		hydrogen_namespace_remove(HYDROGEN_THIS_NAMESPACE, proc.integer);
	}

	if (ret.error == 0) {
		*ret_pid = ret.integer;

		switch (info.si_code) {
			case CLD_EXITED:
				*status = W_EXITCODE(info.si_status & 0xff, 0);
				break;
			case CLD_KILLED:
				*status = W_EXITCODE(0, info.si_status & 0x7f);
				break;
			case CLD_DUMPED:
				*status = W_EXITCODE(0, WCOREFLAG | (info.si_status & 0x7f));
				break;
			case CLD_STOPPED:
				*status = W_EXITCODE(info.si_status & 0x7f, 0x7f);
				break;
			case CLD_CONTINUED:
				*status = 0xffff;
				break;
			default:
				__ensure(!"unreachable");
				break;
		}
	}

	return ret.error;
}

int sys_execve(const char *path, char *const *argv, char *const *envp) {
	size_t argc = 0;
	size_t envc = 0;

	while (argv[argc]) {
		argc++;
	}

	while (envp[envc]) {
		envc++;
	}

	// have to use alloca here because this function needs to be async-signal-safe
	auto *strings = reinterpret_cast<hydrogen_string_t *>(
	    __builtin_alloca((argc + envc) * sizeof(hydrogen_string_t))
	);

	for (size_t i = 0; i < argc; i++) {
		strings[i].data = argv[i];
		strings[i].size = strlen(argv[i]);
	}

	for (size_t i = 0; i < envc; i++) {
		strings[argc + i].data = envp[i];
		strings[argc + i].size = strlen(envp[i]);
	}

	hydrogen_ret_t image =
	    hydrogen_fs_open(HYDROGEN_INVALID_HANDLE, path, strlen(path), O_CLOEXEC | O_CLOFORK, 0);

	if (image.error) {
		return image.error;
	}

	hydrogen_ret_t ret = hydrogen_thread_exec(
	    HYDROGEN_THIS_PROCESS,
	    HYDROGEN_THIS_NAMESPACE,
	    image.integer,
	    argc,
	    strings,
	    envc,
	    &strings[argc],
	    0
	);

	hydrogen_namespace_remove(HYDROGEN_THIS_NAMESPACE, image.integer);
	return ret.error;
}

pid_t sys_getpid() { return hydrogen_process_getpid(HYDROGEN_THIS_PROCESS).integer; }

int sys_kill(int pid, int sig) {
	if (pid > 0) {
		hydrogen_ret_t proc = hydrogen_process_find(pid, 0);

		if (proc.error) {
			return proc.error;
		}

		int error = hydrogen_process_send_signal(proc.integer, sig);
		hydrogen_namespace_remove(HYDROGEN_THIS_NAMESPACE, proc.integer);
		return error;
	} else if (pid == 0) {
		return hydrogen_process_group_send_signal(
		    hydrogen_process_getpgid(HYDROGEN_THIS_PROCESS).integer, sig
		);
	} else if (pid == -1) {
		return hydrogen_process_send_signal(HYDROGEN_INVALID_HANDLE, sig);
	} else {
		return hydrogen_process_group_send_signal(-pid, sig);
	}
}

int sys_readv(int fd, const struct iovec *iovs, int iovc, ssize_t *bytes_read) {
	if (iovc <= 0) {
		return EINVAL;
	}

	size_t total = 0;

	for (int i = 0; i < iovc; i++) {
		total += iovs[i].iov_len;

		if (total > SSIZE_MAX) {
			return EINVAL;
		}
	}

	size_t read = 0;

	for (int i = 0; i < iovc; i++) {
		const struct iovec *vec = &iovs[i];
		size_t done = 0;

		while (done < vec->iov_len) {
			hydrogen_ret_t ret = hydrogen_fs_read(
			    fd,
			    reinterpret_cast<void *>(reinterpret_cast<char *>(vec->iov_base) + done),
			    vec->iov_len - done
			);

			if (ret.error) {
				if (read != 0) {
					*bytes_read = read;
					return 0;
				}

				return ret.error;
			}

			done += ret.integer;
			read += ret.integer;
		}
	}

	return 0;
}

int sys_pwrite(int fd, const void *buf, size_t n, off_t off, ssize_t *bytes_read) {
	if (n > SSIZE_MAX) {
		n = SSIZE_MAX;
	}

	hydrogen_ret_t ret = hydrogen_fs_pwrite(fd, buf, n, off);

	if (ret.error == 0) {
		*bytes_read = ret.integer;
	}

	return ret.error;
}

int sys_access(const char *path, int mode) { return sys_faccessat(AT_FDCWD, path, mode, 0); }

int sys_faccessat(int dirfd, const char *pathname, int mode, int flags) {
	if (dirfd == AT_FDCWD) {
		dirfd = HYDROGEN_INVALID_HANDLE;
	}

	uint32_t type = 0;

	if (mode & R_OK) {
		type |= HYDROGEN_FILE_READ;
	}

	if (mode & W_OK) {
		type |= HYDROGEN_FILE_WRITE;
	}

	if (mode & X_OK) {
		type |= HYDROGEN_FILE_EXEC;
	}

	return hydrogen_fs_access(dirfd, pathname, strlen(pathname), type, flags);
}

int sys_dup(int fd, int flags, int *newfd) {
	uint32_t real_flags = 0;

	if ((flags & O_CLOEXEC) == 0) {
		real_flags |= HYDROGEN_HANDLE_EXEC_KEEP;
	}

	if ((flags & O_CLOFORK) == 0) {
		real_flags |= HYDROGEN_HANDLE_CLONE_KEEP;
	}

	hydrogen_ret_t ret = hydrogen_namespace_add(
	    HYDROGEN_THIS_NAMESPACE, fd, HYDROGEN_THIS_NAMESPACE, -1, -1, real_flags
	);

	if (ret.error == 0) {
		*newfd = ret.integer;
	}

	return ret.error;
}

int sys_dup2(int fd, int flags, int newfd) {
	if (newfd < 0) {
		return EINVAL;
	}

	uint32_t real_flags = 0;

	if ((flags & O_CLOEXEC) == 0) {
		real_flags |= HYDROGEN_HANDLE_EXEC_KEEP;
	}

	if ((flags & O_CLOFORK) == 0) {
		real_flags |= HYDROGEN_HANDLE_CLONE_KEEP;
	}

	hydrogen_ret_t ret = hydrogen_namespace_add(
	    HYDROGEN_THIS_NAMESPACE, fd, HYDROGEN_THIS_NAMESPACE, newfd, -1, real_flags
	);
	return ret.error;
}

int sys_stat(fsfd_target fsfdt, int fd, const char *path, int flags, struct stat *statbuf) {
	int error;
	hydrogen_file_information_t info;

	switch (fsfdt) {
		case mlibc::fsfd_target::fd:
			error = hydrogen_fs_fstat(fd, &info);
			break;
		case mlibc::fsfd_target::path:
			fd = AT_FDCWD;
			[[fallthrough]];
		case mlibc::fsfd_target::fd_path:
			if (fd == AT_FDCWD) {
				fd = HYDROGEN_INVALID_HANDLE;
			}

			error = hydrogen_fs_stat(fd, path, strlen(path), &info, flags);
			break;
		default:
			return EINVAL;
	}

	if (error) {
		return error;
	}

	statbuf->st_dev = info.filesystem_id;
	statbuf->st_ino = info.id;
	statbuf->st_nlink = info.links;
	statbuf->st_blocks = info.blocks;
	statbuf->st_blksize = info.block_size;
	statbuf->st_atim = createTimeSpec(info.atime);
	statbuf->st_ctim = createTimeSpec(info.ctime);
	statbuf->st_mtim = createTimeSpec(info.mtime);
	statbuf->st_mode = info.mode;
	statbuf->st_uid = info.uid;
	statbuf->st_gid = info.gid;

	switch (info.type) {
		case HYDROGEN_REGULAR_FILE:
			statbuf->st_mode |= S_IFREG;
			break;
		case HYDROGEN_DIRECTORY:
			statbuf->st_mode |= S_IFDIR;
			break;
		case HYDROGEN_SYMLINK:
			statbuf->st_mode |= S_IFLNK;
			break;
		case HYDROGEN_CHARACTER_DEVICE:
			statbuf->st_mode |= S_IFCHR;
			break;
		case HYDROGEN_BLOCK_DEVICE:
			statbuf->st_mode |= S_IFBLK;
			break;
		case HYDROGEN_FIFO:
			statbuf->st_mode |= S_IFIFO;
			break;
		default:
			__ensure(!"unreachable");
	}

	statbuf->st_rdev = 0;

	return 0;
}

int sys_readlink(const char *path, void *buffer, size_t max_size, ssize_t *length) {
	return sys_readlinkat(AT_FDCWD, path, buffer, max_size, length);
}

int sys_readlinkat(int dirfd, const char *path, void *buffer, size_t max_size, ssize_t *length) {
	if (max_size > SSIZE_MAX) {
		max_size = SSIZE_MAX;
	}

	if (dirfd == AT_FDCWD) {
		dirfd = HYDROGEN_INVALID_HANDLE;
	}

	hydrogen_ret_t ret = hydrogen_fs_readlink(dirfd, path, strlen(path), buffer, max_size);

	if (ret.error == 0) {
		*length = ret.integer <= max_size ? ret.integer : max_size;
	}

	return ret.error;
}

int sys_ftruncate(int fd, size_t size) { return hydrogen_fs_ftruncate(fd, size); }

gid_t sys_getgid() { return hydrogen_process_getgid(HYDROGEN_THIS_PROCESS).integer; }

gid_t sys_getegid() { return hydrogen_process_getegid(HYDROGEN_THIS_PROCESS).integer; }

uid_t sys_getuid() { return hydrogen_process_getuid(HYDROGEN_THIS_PROCESS).integer; }

uid_t sys_geteuid() { return hydrogen_process_geteuid(HYDROGEN_THIS_PROCESS).integer; }

pid_t sys_gettid() { return hydrogen_thread_get_id(HYDROGEN_THIS_THREAD).integer; }

pid_t sys_getppid() { return hydrogen_process_getppid(HYDROGEN_THIS_PROCESS).integer; }

int sys_getpgid(pid_t pid, pid_t *pgid) {
	if (pid == 0) {
		*pgid = hydrogen_process_getpgid(HYDROGEN_THIS_PROCESS).integer;
		return 0;
	}

	hydrogen_ret_t ret = hydrogen_process_find(pid, 0);

	if (ret.error == 0) {
		int proc = ret.integer;
		ret = hydrogen_process_getpgid(proc);
		hydrogen_namespace_remove(HYDROGEN_THIS_NAMESPACE, proc);

		if (ret.error == 0) {
			*pgid = ret.integer;
		}
	}

	return ret.error;
}

int sys_getsid(pid_t pid, pid_t *sid) {
	if (pid == 0) {
		*sid = hydrogen_process_getsid(HYDROGEN_THIS_PROCESS).integer;
		return 0;
	}

	hydrogen_ret_t ret = hydrogen_process_find(pid, 0);

	if (ret.error == 0) {
		int proc = ret.integer;
		ret = hydrogen_process_getsid(proc);
		hydrogen_namespace_remove(HYDROGEN_THIS_NAMESPACE, proc);

		if (ret.error == 0) {
			*sid = ret.integer;
		}
	}

	return ret.error;
}

int sys_setpgid(pid_t pid, pid_t pgid) {
	if (pid == 0) {
		return hydrogen_process_setpgid(HYDROGEN_THIS_PROCESS, pgid);
	}

	hydrogen_ret_t ret = hydrogen_process_find(pid, 0);

	if (ret.error == 0) {
		ret.error = hydrogen_process_setpgid(ret.integer, pgid);
		hydrogen_namespace_remove(HYDROGEN_THIS_NAMESPACE, ret.integer);
	}

	return ret.error;
}

int sys_setuid(uid_t uid) { return hydrogen_process_setuid(HYDROGEN_THIS_PROCESS, uid); }

int sys_seteuid(uid_t uid) { return hydrogen_process_seteuid(HYDROGEN_THIS_PROCESS, uid); }

int sys_setgid(gid_t gid) { return hydrogen_process_setgid(HYDROGEN_THIS_PROCESS, gid); }

int sys_setegid(gid_t gid) { return hydrogen_process_setegid(HYDROGEN_THIS_PROCESS, gid); }

int sys_getgroups(size_t size, gid_t *list, int *ret) {
	hydrogen_ret_t result = hydrogen_process_getgroups(HYDROGEN_THIS_PROCESS, list, size);

	if (result.error == 0) {
		if (size != 0 && size < result.integer) {
			return EINVAL;
		}

		*ret = result.integer;
	}

	return result.error;
}

void sys_yield() { hydrogen_thread_yield(); }

int sys_pselect(
    int num_fds,
    fd_set *read_set,
    fd_set *write_set,
    fd_set *except_set,
    const struct timespec *timeout,
    const sigset_t *sigmask,
    int *num_events
) {
	uint64_t deadline = 0;

	if (timeout) {
		if (timeout->tv_sec || timeout->tv_nsec) {
			deadline = hydrogen_boot_time() + createTimeU64(*timeout);
		} else {
			deadline = 1;
		}
	}

	hydrogen_ret_t ret = hydrogen_event_queue_create(0);

	if (ret.error) {
		return ret.error;
	}

	int queue = ret.integer;
	int error = 0;
	hydrogen_event_t buffer[128];
	size_t total = 0;

	sigset_t orig_mask;

	if (sigmask) {
		int error = sys_sigprocmask(SIG_SETMASK, sigmask, &orig_mask);

		if (error) {
			hydrogen_namespace_remove(HYDROGEN_THIS_NAMESPACE, queue);
			return error;
		}
	}

	for (int i = 0; i < num_fds; i++) {
		if (read_set && FD_ISSET(i, read_set)) {
			error = hydrogen_event_queue_add(
			    queue, i, HYDROGEN_EVENT_FILE_DESCRIPTION_READABLE, 0, (void *)(uintptr_t)i, 0
			);
			if (error && error != EINVAL) {
				goto ret;
			}
		}

		if (write_set && FD_ISSET(i, write_set)) {
			error = hydrogen_event_queue_add(
			    queue, i, HYDROGEN_EVENT_FILE_DESCRIPTION_WRITABLE, 0, (void *)(uintptr_t)i, 0
			);
			if (error && error != EINVAL) {
				goto ret;
			}
		}

		if (except_set && FD_ISSET(i, except_set)) {
			error = hydrogen_event_queue_add(
			    queue, i, HYDROGEN_EVENT_FILE_DESCRIPTION_ERROR_REGULAR, 0, (void *)(uintptr_t)i, 0
			);
			if (error && error != EINVAL) {
				goto ret;
			}
		}
	}

	while (true) {
		hydrogen_ret_t ret =
		    hydrogen_event_queue_wait(queue, buffer, sizeof(buffer) / sizeof(*buffer), deadline);

		if (ret.error) {
			if (total != 0) {
				break;
			}

			if (ret.error == EAGAIN) {
				if (read_set)
					FD_ZERO(read_set);
				if (write_set)
					FD_ZERO(write_set);
				if (except_set)
					FD_ZERO(except_set);
				break;
			}

			error = ret.error;
			goto ret;
		}

		if (total == 0) {
			if (read_set)
				FD_ZERO(read_set);
			if (write_set)
				FD_ZERO(write_set);
			if (except_set)
				FD_ZERO(except_set);
		}

		for (size_t i = 0; i < ret.integer; i++) {
			auto event = &buffer[i];
			int fd = (uintptr_t)event->ctx;

			switch (event->type) {
				case HYDROGEN_EVENT_FILE_DESCRIPTION_READABLE:
					FD_SET(fd, read_set);
					break;
				case HYDROGEN_EVENT_FILE_DESCRIPTION_WRITABLE:
					FD_SET(fd, write_set);
					break;
				case HYDROGEN_EVENT_FILE_DESCRIPTION_ERROR_REGULAR:
					FD_SET(fd, except_set);
					break;
				default:
					__ensure(!"unreachable");
			}

			hydrogen_event_queue_remove(queue, fd, event->type, 0);
		}

		total += ret.integer;

		if (ret.integer < sizeof(buffer) / sizeof(*buffer)) {
			break;
		}

		deadline = 1;
	}

	*num_events = total;
	error = 0;
ret:
	if (sigmask) {
		sys_sigprocmask(SIG_SETMASK, &orig_mask, NULL);
	}

	hydrogen_namespace_remove(HYDROGEN_THIS_NAMESPACE, queue);
	return error;
}

static struct timeval createTimeVal(uint64_t time) {
	return {(time_t)(time / 1'000'000'000), (suseconds_t)((time % 1'000'000'000) / 1'000)};
}

int sys_getrusage(int scope, struct rusage *usage) {
	hydrogen_process_cpu_time_t time;
	int error = hydrogen_process_get_cpu_time(&time);

	if (error) {
		return error;
	}

	uint64_t utime;
	uint64_t ktime;

	switch (scope) {
		case RUSAGE_SELF:
			utime = time.self.user;
			ktime = time.self.kernel;
			break;
		case RUSAGE_CHILDREN:
			utime = time.children.user;
			ktime = time.children.kernel;
			break;
		default:
			return EINVAL;
	}

	usage->ru_utime = createTimeVal(utime);
	usage->ru_stime = createTimeVal(ktime);

	return 0;
}

int sys_getcwd(char *buffer, size_t size) {
	if (size == 0) {
		return EINVAL;
	}

	hydrogen_ret_t ret = hydrogen_fs_fpath(HYDROGEN_INVALID_HANDLE, buffer, size - 1);

	if (ret.error) {
		return ret.error;
	}

	if (ret.integer >= size) {
		return ERANGE;
	}

	buffer[ret.integer] = 0;
	return 0;
}

int sys_chdir(const char *path) {
	return hydrogen_fs_chdir(HYDROGEN_THIS_PROCESS, HYDROGEN_INVALID_HANDLE, path, strlen(path));
}

int sys_fchdir(int fd) { return hydrogen_fs_fchdir(HYDROGEN_THIS_PROCESS, fd); }

int sys_chroot(const char *path) {
	return hydrogen_fs_chroot(HYDROGEN_THIS_PROCESS, HYDROGEN_INVALID_HANDLE, path, strlen(path));
}

int sys_mkdir(const char *path, mode_t mode) { return sys_mkdirat(AT_FDCWD, path, mode); }

int sys_mkdirat(int dirfd, const char *path, mode_t mode) {
	if (dirfd == AT_FDCWD) {
		dirfd = HYDROGEN_INVALID_HANDLE;
	}

	return hydrogen_fs_create(dirfd, path, strlen(path), HYDROGEN_DIRECTORY, mode);
}

int sys_link(const char *old_path, const char *new_path) {
	return sys_linkat(AT_FDCWD, old_path, AT_FDCWD, new_path, 0);
}

int sys_linkat(int olddirfd, const char *old_path, int newdirfd, const char *new_path, int flags) {
	if (olddirfd == AT_FDCWD) {
		olddirfd = HYDROGEN_INVALID_HANDLE;
	}

	if (newdirfd == AT_FDCWD) {
		newdirfd = HYDROGEN_INVALID_HANDLE;
	}

	return hydrogen_fs_link(
	    olddirfd, old_path, strlen(old_path), newdirfd, new_path, strlen(new_path), flags
	);
}

int sys_symlink(const char *target_path, const char *link_path) {
	return sys_symlinkat(target_path, AT_FDCWD, link_path);
}

int sys_symlinkat(const char *target_path, int dirfd, const char *link_path) {
	if (dirfd == AT_FDCWD) {
		dirfd = HYDROGEN_INVALID_HANDLE;
	}

	return hydrogen_fs_symlink(
	    dirfd, link_path, strlen(link_path), target_path, strlen(target_path)
	);
}

int sys_fcntl(int fd, int request, va_list args, int *result) {
	if (fd < 0) {
		return EBADF;
	}

	hydrogen_ret_t ret;

	switch (request) {
		case F_DUPFD: {
			int min = va_arg(args, int);

			if (min < 0) {
				return EINVAL;
			}

			ret = hydrogen_namespace_add(
			    HYDROGEN_THIS_NAMESPACE,
			    fd,
			    HYDROGEN_THIS_NAMESPACE,
			    -min - 1,
			    -1,
			    HYDROGEN_HANDLE_CLONE_KEEP | HYDROGEN_HANDLE_EXEC_KEEP
			);
			break;
		}
		case F_GETFD: {
			uint32_t flags;
			ret.error = hydrogen_namespace_resolve(HYDROGEN_THIS_NAMESPACE, fd, NULL, &flags);

			if (ret.error == 0) {
				ret.integer = 0;

				if ((flags & HYDROGEN_HANDLE_CLONE_KEEP) == 0) {
					ret.integer |= FD_CLOFORK;
				}

				if ((flags & HYDROGEN_HANDLE_EXEC_KEEP) == 0) {
					ret.integer |= FD_CLOEXEC;
				}
			}

			break;
		}
		case F_SETFD: {
			int orig_flags = va_arg(args, int);
			uint32_t flags = 0;

			if ((orig_flags & FD_CLOEXEC) == 0) {
				flags |= HYDROGEN_HANDLE_EXEC_KEEP;
			}

			if ((orig_flags & FD_CLOFORK) == 0) {
				flags |= HYDROGEN_HANDLE_CLONE_KEEP;
			}

			ret = hydrogen_namespace_add(
			    HYDROGEN_THIS_NAMESPACE, fd, HYDROGEN_THIS_NAMESPACE, fd, -1, flags
			);
			break;
		}
		case F_GETFL:
			ret = hydrogen_fs_fflags(fd, -1);
			break;
		case F_SETFL: {
			int flags = va_arg(args, int);

			if (flags < 0) {
				return EINVAL;
			}

			ret = hydrogen_fs_fflags(fd, flags);
			ret.integer = 0;
			break;
		}
		default:
			return EINVAL;
	}

	if (ret.error == 0) {
		*result = ret.integer;
	}

	return ret.error;
}

int sys_ttyname(int fd, char *buf, size_t size) {
	if (size == 0) {
		return ERANGE;
	}

	hydrogen_ret_t ret = hydrogen_fs_fpath(fd, buf, size - 1);

	if (ret.error) {
		return ret.error;
	}

	if (ret.integer >= size) {
		return ERANGE;
	}

	buf[ret.integer] = 0;
	return 0;
}

int sys_chmod(const char *pathname, mode_t mode) {
	return sys_fchmodat(AT_FDCWD, pathname, mode, 0);
}

int sys_fchmod(int fd, mode_t mode) { return hydrogen_fs_fchmod(fd, mode); }

int sys_fchmodat(int fd, const char *pathname, mode_t mode, int flags) {
	if (fd == AT_FDCWD) {
		fd = HYDROGEN_INVALID_HANDLE;
	}

	return hydrogen_fs_chmod(fd, pathname, strlen(pathname), mode, flags);
}

int sys_utimensat(int dirfd, const char *pathname, const struct timespec *times, int flags) {
	if (dirfd == AT_FDCWD) {
		dirfd = HYDROGEN_INVALID_HANDLE;
	}

	__int128_t atime = HYDROGEN_FILE_TIME_NOW;
	__int128_t ctime = HYDROGEN_FILE_TIME_NOW;
	__int128_t mtime = HYDROGEN_FILE_TIME_NOW;

	if (times) {
		if (times[0].tv_nsec != UTIME_NOW) {
			atime = times[0].tv_nsec != UTIME_OMIT ? createTime(times[0]) : HYDROGEN_FILE_TIME_OMIT;
		}

		if (times[1].tv_nsec != UTIME_NOW) {
			mtime = times[1].tv_nsec != UTIME_OMIT ? createTime(times[1]) : HYDROGEN_FILE_TIME_OMIT;
		}
	}

	return hydrogen_fs_utime(dirfd, pathname, strlen(pathname), atime, ctime, mtime, flags);
}

int sys_setsid(pid_t *sid) {
	hydrogen_ret_t ret = hydrogen_process_setsid(HYDROGEN_THIS_PROCESS);

	if (ret.error == 0) {
		*sid = ret.integer;
	}

	return ret.error;
}

int sys_pipe(int *fds, int flags) { return hydrogen_fs_pipe(fds, flags); }

static int
maybeAddPoll(int queue, struct pollfd *fd, int mask, hydrogen_event_type_t type, int flags) {
	if ((fd->events & mask) == mask) {
		int error = hydrogen_event_queue_add(queue, fd->fd, type, 0, fd, flags);

		if (error == EBADF) {
			error = 0;
			fd->revents |= POLLNVAL;
		} else if (error == EINVAL) {
			error = 0;
		}

		return error;
	}

	return 0;
}

int sys_poll(struct pollfd *fds, nfds_t count, int timeout, int *num_events) {
	static struct {
		int mask;
		hydrogen_event_type_t type;
		int flags;
	} poll_events[] = {
	    {POLLIN, HYDROGEN_EVENT_FILE_DESCRIPTION_READABLE, 0},
	    {POLLOUT, HYDROGEN_EVENT_FILE_DESCRIPTION_WRITABLE, 0},
	    {0, HYDROGEN_EVENT_FILE_DESCRIPTION_ERROR, HYDROGEN_EVENT_NO_WAKE},
	    {0, HYDROGEN_EVENT_FILE_DESCRIPTION_DISCONNECTED, HYDROGEN_EVENT_NO_WAKE},
	};

	uint64_t deadline = 0;

	if (timeout >= 0) {
		if (timeout > 0) {
			deadline = hydrogen_boot_time() + timeout * 1'000'000ull;
		} else {
			deadline = 1;
		}
	}

	hydrogen_ret_t ret = hydrogen_event_queue_create(0);

	if (ret.error) {
		return ret.error;
	}

	int queue = ret.integer;
	int error = 0;
	hydrogen_event_t buffer[128];
	size_t total = 0;

	for (nfds_t i = 0; i < count; i++) {
		struct pollfd *fd = &fds[i];
		fd->revents = 0;

		if (fd->fd >= 0) {
			for (auto &event : poll_events) {
				int error = maybeAddPoll(queue, fd, event.mask, event.type, event.flags);
				if (error)
					goto ret;
			}
		}
	}

	while (true) {
		hydrogen_ret_t ret =
		    hydrogen_event_queue_wait(queue, buffer, sizeof(buffer) / sizeof(*buffer), deadline);

		if (ret.error) {
			if (ret.error == EAGAIN || total != 0)
				break;

			error = ret.error;
			goto ret;
		}

		for (size_t i = 0; i < ret.integer; i++) {
			auto event = &buffer[i];
			auto fd = reinterpret_cast<struct pollfd *>(event->ctx);

			switch (event->type) {
				case HYDROGEN_EVENT_FILE_DESCRIPTION_READABLE:
					fd->revents |= POLLIN;
					break;
				case HYDROGEN_EVENT_FILE_DESCRIPTION_WRITABLE:
					fd->revents |= POLLOUT;
					break;
				case HYDROGEN_EVENT_FILE_DESCRIPTION_ERROR:
					fd->revents |= POLLERR;
					break;
				case HYDROGEN_EVENT_FILE_DESCRIPTION_DISCONNECTED:
					fd->revents |= POLLHUP;
					break;
				default:
					__ensure(!"unreachable");
			}

			hydrogen_event_queue_remove(queue, fd->fd, event->type, 0);
		}

		total += ret.integer;

		if (ret.integer < sizeof(buffer) / sizeof(*buffer)) {
			break;
		}

		deadline = 1;
	}

	*num_events = total;
	error = 0;
ret:
	hydrogen_namespace_remove(HYDROGEN_THIS_NAMESPACE, ret.integer);
	return error;
}

int sys_ioctl(int fd, unsigned long request, void *arg, int *result) {
	size_t size;

	switch (request) {
		case __IOCTL_MEM_ALLOCATE:
			size = sizeof(hydrogen_ioctl_mem_allocate_t);
			break;
		case __IOCTL_MEM_IS_RAM:
			size = sizeof(hydrogen_ioctl_mem_is_ram_t);
			break;
		case __IOCTL_MEM_NEXT_RAM_RANGE:
			size = sizeof(hydrogen_ioctl_mem_next_ram_range_t);
			break;
		case __IOCTL_IRQ_OPEN:
			size = sizeof(hydrogen_ioctl_irq_open_t);
			break;
		case __IOCTL_PTM_GET_NUMBER:
		case __IOCTL_PTM_GET_LOCKED:
			size = 0;
			break;
		case __IOCTL_PTM_OPEN_SLAVE:
		case __IOCTL_PTM_SET_LOCKED:
			size = sizeof(int);
			break;
		case __IOCTL_PTY_GET_SETTINGS:
		case __IOCTL_PTY_SET_SETTINGS:
		case __IOCTL_PTY_SET_SETTINGS_DRAIN:
		case __IOCTL_PTY_SET_SETTINGS_FLUSH:
			size = sizeof(struct __termios);
			break;
		default:
			return ENOTTY;
	}

	hydrogen_ret_t ret = hydrogen_fs_ioctl(fd, request, arg, size);

	if (ret.error == 0) {
		*result = ret.integer;
	}

	return ret.error;
}

int sys_sigtimedwait(
    const sigset_t *__restrict set,
    siginfo_t *__restrict info,
    const struct timespec *__restrict timeout,
    int *out_signal
) {
	uint64_t deadline = 0;

	if (timeout) {
		if (timeout->tv_sec || timeout->tv_nsec) {
			deadline = hydrogen_boot_time() + createTimeU64(*timeout);
		} else {
			deadline = 1;
		}
	}

	int error =
	    hydrogen_process_sigwait(HYDROGEN_THIS_PROCESS, mlibcSigsetToKernel(*set), info, deadline);

	if (error == 0) {
		*out_signal = info->si_signo;
	}

	return error;
}

int sys_gethostname(char *buffer, size_t bufsize) {
	if (bufsize == 0) {
		return ENAMETOOLONG;
	}

	hydrogen_ret_t ret = hydrogen_get_host_name(buffer, bufsize - 1);

	if (ret.error) {
		return ret.error;
	}

	if (ret.integer >= bufsize) {
		return ENAMETOOLONG;
	}

	buffer[ret.integer] = 0;
	return 0;
}

int sys_sethostname(const char *buffer, size_t bufsize) {
	return hydrogen_set_host_name(buffer, bufsize);
}

int sys_mkfifoat(int dirfd, const char *path, mode_t mode) {
	if (dirfd == AT_FDCWD) {
		dirfd = HYDROGEN_INVALID_HANDLE;
	}

	return hydrogen_fs_create(dirfd, path, strlen(path), HYDROGEN_FIFO, mode);
}

int sys_mknodat(int dirfd, const char *path, int mode, int) {
	if (dirfd == AT_FDCWD) {
		dirfd = HYDROGEN_INVALID_HANDLE;
	}

	hydrogen_file_type_t type;

	switch (mode & S_IFMT) {
		case S_IFREG:
			type = HYDROGEN_REGULAR_FILE;
			break;
		case S_IFDIR:
			type = HYDROGEN_DIRECTORY;
			break;
		case S_IFLNK:
			type = HYDROGEN_SYMLINK;
			break;
		case S_IFCHR:
			type = HYDROGEN_CHARACTER_DEVICE;
			break;
		case S_IFBLK:
			type = HYDROGEN_BLOCK_DEVICE;
			break;
		case S_IFIFO:
			type = HYDROGEN_FIFO;
			break;
		default:
			return EINVAL;
	}

	return hydrogen_fs_create(dirfd, path, strlen(path), type, mode);
}

int sys_umask(mode_t mode, mode_t *old) {
	*old = hydrogen_fs_umask(HYDROGEN_THIS_PROCESS, mode).integer;
	return 0;
}

int sys_tgkill(int tgid, int tid, int sig) {
	hydrogen_ret_t proc = hydrogen_process_find(tgid, 0);

	if (proc.error) {
		return proc.error;
	}

	hydrogen_ret_t ret = hydrogen_thread_find(proc.integer, tid, 0);
	hydrogen_namespace_remove(HYDROGEN_THIS_NAMESPACE, proc.integer);

	if (ret.error) {
		return ret.error;
	}

	int error = hydrogen_thread_send_signal(ret.integer, sig);
	hydrogen_namespace_remove(HYDROGEN_THIS_NAMESPACE, ret.integer);
	return error;
}

int sys_fchownat(int dirfd, const char *pathname, uid_t owner, gid_t group, int flags) {
	if (flags & AT_EMPTY_PATH) {
		return hydrogen_fs_fchown(dirfd, owner, group);
	}

	if (dirfd == AT_FDCWD) {
		dirfd = HYDROGEN_INVALID_HANDLE;
	}

	return hydrogen_fs_chown(dirfd, pathname, strlen(pathname), owner, group, flags);
}

int sys_sigaltstack(const stack_t *ss, stack_t *oss) {
	return hydrogen_thread_sigaltstack(ss, oss);
}

int sys_sigsuspend(const sigset_t *set) {
	return hydrogen_thread_sigsuspend(mlibcSigsetToKernel(*set));
}

int sys_sigpending(sigset_t *set) {
	*set = kernelSigsetToMlibc(hydrogen_thread_sigpending());
	return 0;
}

int sys_setgroups(size_t size, const gid_t *list) {
	return hydrogen_process_setgroups(HYDROGEN_THIS_PROCESS, list, size);
}

int sys_times(struct tms *tms, clock_t *out) {
	hydrogen_process_cpu_time_t time;
	int error = hydrogen_process_get_cpu_time(&time);

	if (error) {
		return error;
	}

	tms->tms_utime = time.self.user / 1000;
	tms->tms_stime = time.self.kernel / 1000;
	tms->tms_cutime = time.children.user / 1000;
	tms->tms_cstime = time.children.kernel / 1000;
	*out = hydrogen_boot_time() / 1000;
	return 0;
}

static void terminate(char *buffer, size_t size, size_t full_size) {
	buffer[full_size < size ? full_size : size] = 0;
}

static void fill_buffer(char *buffer, size_t size, size_t (*func)(void *, size_t)) {
	terminate(buffer, size, func(buffer, size));
}

extern const char *hydrogen_machine_name();

static size_t get_machine_name(void *buffer, size_t size) {
	const char *name = hydrogen_machine_name();
	size_t full_size = strlen(name);
	memcpy(buffer, name, full_size < size ? full_size : size);
	return full_size;
}

int sys_uname(struct utsname *buf) {
	hydrogen_ret_t ret = hydrogen_get_host_name(buf->nodename, sizeof(buf->nodename) - 1);

	if (ret.error) {
		return ret.error;
	}

	terminate(buf->nodename, sizeof(buf->nodename), ret.integer);
	fill_buffer(buf->machine, sizeof(buf->machine), get_machine_name);
	fill_buffer(buf->release, sizeof(buf->release), hydrogen_get_kernel_release);
	fill_buffer(buf->sysname, sizeof(buf->sysname), hydrogen_get_kernel_name);
	fill_buffer(buf->version, sizeof(buf->version), hydrogen_get_kernel_version);

	return 0;
}

int sys_pause() { return hydrogen_thread_sleep(0); }

int sys_setresuid(uid_t ruid, uid_t euid, uid_t suid) {
	return hydrogen_process_setresuid(HYDROGEN_THIS_PROCESS, ruid, euid, suid);
}

int sys_setresgid(gid_t rgid, gid_t egid, gid_t sgid) {
	return hydrogen_process_setresgid(HYDROGEN_THIS_PROCESS, rgid, egid, sgid);
}

int sys_getresuid(uid_t *ruid, uid_t *euid, uid_t *suid) {
	uint32_t ids[3];
	int error = hydrogen_process_getresuid(HYDROGEN_THIS_PROCESS, ids);

	if (error == 0) {
		*ruid = ids[0];
		*euid = ids[1];
		*suid = ids[2];
	}

	return error;
}

int sys_getresgid(gid_t *rgid, gid_t *egid, gid_t *sgid) {
	uint32_t ids[3];
	int error = hydrogen_process_getresgid(HYDROGEN_THIS_PROCESS, ids);

	if (error == 0) {
		*rgid = ids[0];
		*egid = ids[1];
		*sgid = ids[2];
	}

	return error;
}

int sys_setreuid(uid_t ruid, uid_t euid) {
	return hydrogen_process_setreuid(HYDROGEN_THIS_PROCESS, ruid, euid);
}

int sys_setregid(gid_t rgid, gid_t egid) {
	return hydrogen_process_setregid(HYDROGEN_THIS_PROCESS, rgid, egid);
}

int sys_waitid(idtype_t idtype, id_t id, siginfo_t *info, int options) {
	uint32_t real_flags = 0;
	uint64_t deadline = 0;

	if ((options & WEXITED) == WEXITED) {
		real_flags |= HYDROGEN_PROCESS_WAIT_EXITED | HYDROGEN_PROCESS_WAIT_KILLED;
	}

	if ((options & WCONTINUED) == WCONTINUED) {
		real_flags |= HYDROGEN_PROCESS_WAIT_CONTINUED;
	}

	if ((options & WSTOPPED) == WSTOPPED) {
		real_flags |= HYDROGEN_PROCESS_WAIT_STOPPED;
	}

	if ((options & WNOWAIT) != WNOWAIT) {
		real_flags |= HYDROGEN_PROCESS_WAIT_DISCARD;
	}

	if ((options & WNOHANG) == WNOHANG) {
		deadline = 1;
	}

	hydrogen_ret_t ret;

	switch (idtype) {
		case P_ALL:
			ret = hydrogen_process_wait_id(0, real_flags, info, deadline);
			break;
		case P_PID: {
			ret = hydrogen_process_find(id, 0);

			if (ret.error == 0) {
				ret.error = hydrogen_process_wait(ret.integer, real_flags, info, deadline);
				hydrogen_namespace_remove(HYDROGEN_THIS_NAMESPACE, ret.integer);
			}

			break;
		}
		case P_PGID:
			if (id == 0) {
				return ECHILD;
			}

			ret = hydrogen_process_wait_id(id, real_flags, info, deadline);
			break;
		default:
			return EINVAL;
	}

	return ret.error;
}

int sys_ptsname(int fd, char *buffer, size_t length) {
	hydrogen_ret_t ret = hydrogen_fs_ioctl(fd, __IOCTL_PTM_GET_NUMBER, NULL, 0);

	if (ret.error == 0) {
		if ((size_t)snprintf(buffer, length, "/dev/pts/%zu", ret.integer) >= length) {
			return ERANGE;
		}
	}

	return ret.error;
}

int sys_unlockpt(int fd) {
	int locked = 0;
	return hydrogen_fs_ioctl(fd, __IOCTL_PTM_SET_LOCKED, &locked, sizeof(locked)).error;
}

int sys_isatty(int fd) {
	struct __termios settings;
	return hydrogen_fs_ioctl(fd, __IOCTL_PTY_GET_SETTINGS, &settings, sizeof(settings)).error;
}

int sys_tcgetattr(int fd, struct termios *attr) {
	struct termios value = {};
	hydrogen_ret_t ret =
	    hydrogen_fs_ioctl(fd, __IOCTL_PTY_GET_SETTINGS, &value.__base, sizeof(value.__base));

	if (ret.error == 0) {
		*attr = value;
	}

	return ret.error;
}

int sys_tcsetattr(int fd, int optional_actions, const struct termios *attr) {
	int request;

	switch (optional_actions) {
		case TCSANOW:
			request = __IOCTL_PTY_SET_SETTINGS;
			break;
		case TCSADRAIN:
			request = __IOCTL_PTY_SET_SETTINGS_DRAIN;
			break;
		case TCSAFLUSH:
			request = __IOCTL_PTY_SET_SETTINGS_FLUSH;
			break;
		default:
			return EINVAL;
	}

	hydrogen_ret_t ret = hydrogen_fs_ioctl(
	    fd, request, const_cast<struct __termios *>(&attr->__base), sizeof(attr->__base)
	);
	return ret.error;
}
}; // namespace mlibc
