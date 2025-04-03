#ifndef	_UNISTD_H
#define	_UNISTD_H

#ifdef __cplusplus
extern "C" {
#endif

#include <features.h>

#define STDIN_FILENO	0
#define STDOUT_FILENO	1
#define STDERR_FILENO	2

#define SEEK_SET	0
#define SEEK_CUR	1
#define SEEK_END	2
#define SEEK_DATA	3
#define SEEK_HOLE	4

#define F_OK		0
#define R_OK		4
#define W_OK		2
#define X_OK		1


#if __cplusplus >= 201103L
#define NULL nullptr
#elif defined(__cplusplus)
#define NULL 0L
#else
#define NULL ((void*)0)
#endif

#define __NEED_size_t
#define __NEED_ssize_t
#define __NEED_uid_t
#define __NEED_gid_t
#define __NEED_off_t
#define __NEED_pid_t
#define __NEED_intptr_t
#define __NEED_useconds_t

#include <bits/alltypes.h>

#include <errno.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <urchin.h>

static inline int access(const char *filename, int mode);
static inline int access(const char *filename, int mode)
{
	register const char *_filename __asm__("rdi") = filename;
	register int _mode __asm__("esi") = mode;
	__asm__("mov {%0, %%eax | eax, %0}" :: "i" (SYS_access),  "r" (_filename), "r" (_mode) : "eax");
	int ret;
	__asm__ volatile("syscall" : "=a" (ret) :: "rcx", "r11");
	return ret;
}

unsigned alarm(unsigned);
/*
static inline unsigned int alarm(unsigned int seconds);
static inline unsigned int alarm(unsigned int seconds)
{
	register unsigned int _seconds __asm__("edi") = seconds;
	__asm__("mov {%0, %%eax | eax, %0}" :: "i" (SYS_alarm),  "r" (_seconds) : "eax");
	unsigned int ret;
	__asm__ volatile("syscall" : "=a" (ret) :: "rcx", "r11");
	return ret;
}
*/

static inline int chown(const char *filename, uid_t user, gid_t group);
static inline int chown(const char *filename, uid_t user, gid_t group)
{
	register const char *_filename __asm__("rdi") = filename;
	register uid_t _user __asm__("esi") = user;
	register gid_t _group __asm__("edx") = group;
	__asm__("mov {%0, %%eax | eax, %0}" :: "i" (SYS_chown),  "r" (_filename), "r" (_user), "r" (_group) : "eax");
	int ret;
	__asm__ volatile("syscall" : "=a" (ret) :: "rcx", "r11");
	return __syscall_ret(ret);
}

int close(int);
/*
static inline int close(unsigned int fd);
static inline int close(unsigned int fd)
{
	register unsigned int _fd __asm__("edi") = fd;
	__asm__("mov {%0, %%eax | eax, %0}" :: "i" (SYS_close),  "r" (_fd) : "eax");
	int ret;
	__asm__ volatile("syscall" : "=a" (ret) :: "rcx", "r11");
	return ret;
}
*/
/* For some reason the POSIX standard allows negative file descriptors,
 * when in linux you can't have one. Unfortuantely I have to change
 * unsigned int to just int.
 */
static inline int dup(int fildes);
static inline int dup(int fildes)
{
	register int _fildes __asm__("edi") = fildes;
	__asm__("mov {%0, %%eax | eax, %0}" :: "i" (SYS_dup),  "r" (_fildes) : "eax");
	int ret;
	__asm__ volatile("syscall" : "=a" (ret) :: "rcx", "r11");
	return ret;
}

static inline int dup2(int oldfd, int newfd);
static inline int dup2(int oldfd, int newfd)
{
	register unsigned int _oldfd __asm__("edi") = oldfd;
	register unsigned int _newfd __asm__("esi") = newfd;
	__asm__("mov {%0, %%eax | eax, %0}" :: "i" (SYS_dup2),  "r" (_oldfd), "r" (_newfd) : "eax");
	int ret;
	__asm__ volatile("syscall" : "=a" (ret) :: "rcx", "r11");
	return ret;
}

static inline int dup3(int oldfd, int newfd, int flags);
static inline int dup3(int oldfd, int newfd, int flags)
{
	register unsigned int _oldfd __asm__("edi") = oldfd;
	register unsigned int _newfd __asm__("esi") = newfd;
	register int _flags __asm__("edx") = flags;
	__asm__("mov {%0, %%eax | eax, %0}" :: "i" (SYS_dup3),  "r" (_oldfd), "r" (_newfd), "r" (_flags) : "eax");
	int ret;
	__asm__ volatile("syscall" : "=a" (ret) :: "rcx", "r11");
	return ret;
}

static inline int execve(const char *filename, char *const *argv, char *const *envp);
static inline int execve(const char *filename, char *const *argv, char *const *envp)
{
	register const char *_filename __asm__("rdi") = filename;
	register char *const *_argv __asm__("rsi") = argv;
	register char *const *_envp __asm__("rdx") = envp;
	__asm__("mov {%0, %%eax | eax, %0}" :: "i" (SYS_execve),  "r" (_filename), "r" (_argv), "r" (_envp) : "eax");
	int ret;
	__asm__ volatile("syscall" : "=a" (ret) :: "rcx", "r11");
	return __syscall_ret(ret);
}

int faccessat(int, const char *, int, int);
/*
static inline int faccessat(int dfd, const char *filename, int mode);
static inline int faccessat(int dfd, const char *filename, int mode)
{
	register int _dfd __asm__("edi") = dfd;
	register const char *_filename __asm__("rsi") = filename;
	register int _mode __asm__("edx") = mode;
	__asm__("mov {%0, %%eax | eax, %0}" :: "i" (SYS_faccessat),  "r" (_dfd), "r" (_filename), "r" (_mode) : "eax");
	int ret;
	__asm__ volatile("syscall" : "=a" (ret) :: "rcx", "r11");
	return ret;
}
*/
int fchdir(int);
/*
static inline int fchdir(unsigned int fd);
static inline int fchdir(unsigned int fd)
{
	register unsigned int _fd __asm__("edi") = fd;
	__asm__("mov {%0, %%eax | eax, %0}" :: "i" (SYS_fchdir),  "r" (_fd) : "eax");
	int ret;
	__asm__ volatile("syscall" : "=a" (ret) :: "rcx", "r11");
	return ret;
}
*/
int fchown(int, uid_t, gid_t);
/*
static inline int fchown(unsigned int fd, uid_t user, gid_t group);
static inline int fchown(unsigned int fd, uid_t user, gid_t group)
{
	register unsigned int _fd __asm__("edi") = fd;
	register uid_t _user __asm__("esi") = user;
	register gid_t _group __asm__("edx") = group;
	__asm__("mov {%0, %%eax | eax, %0}" :: "i" (SYS_fchown),  "r" (_fd), "r" (_user), "r" (_group) : "eax");
	int ret;
	__asm__ volatile("syscall" : "=a" (ret) :: "rcx", "r11");
	return ret;
}
*/
static inline int fchownat(int dfd, const char *filename, uid_t user, gid_t group, int flag);
static inline int fchownat(int dfd, const char *filename, uid_t user, gid_t group, int flag)
{
	register int _dfd __asm__("edi") = dfd;
	register const char *_filename __asm__("rsi") = filename;
	register uid_t _user __asm__("edx") = user;
	register gid_t _group __asm__("r8d") = group;
	register int _flag __asm__("r9d") = flag;
	__asm__("mov {%0, %%eax | eax, %0}" :: "i" (SYS_fchownat),  "r" (_dfd), "r" (_filename), "r" (_user), "r" (_group), "r" (_flag) : "eax");
	int ret;
	__asm__ volatile("syscall" : "=a" (ret) :: "rcx", "r11");
	return ret;
}

static inline int fdatasync(int fd);
static inline int fdatasync(int fd)
{
	register unsigned int _fd __asm__("edi") = fd;
	__asm__("mov {%0, %%eax | eax, %0}" :: "i" (SYS_fdatasync),  "r" (_fd) : "eax");
	int ret;
	__asm__ volatile("syscall" : "=a" (ret) :: "rcx", "r11");
	return ret;
}

pid_t fork(void);
/*
static inline int fork(void);
static inline int fork(void)
{
	__asm__("mov {%0, %%eax | eax, %0}" :: "i" (SYS_fork) : "eax");
	int ret;
	__asm__ volatile("syscall" : "=a" (ret) :: "rcx", "r11");
	return ret;
}
*/
int fsync(int);
/*
static inline int fsync(unsigned int fd);
static inline int fsync(unsigned int fd)
{
	register unsigned int _fd __asm__("edi") = fd;
	__asm__("mov {%0, %%eax | eax, %0}" :: "i" (SYS_fsync),  "r" (_fd) : "eax");
	int ret;
	__asm__ volatile("syscall" : "=a" (ret) :: "rcx", "r11");
	return ret;
}
*/
static inline int ftruncate(int fd, off_t length);
static inline int ftruncate(int fd, off_t length)
{
	register int _fd __asm__("edi") = fd;
	register off_t _length __asm__("esi") = length;
	__asm__("mov {%0, %%eax | eax, %0}" :: "i" (SYS_ftruncate),  "r" (_fd), "r" (_length) : "eax");
	int ret;
	__asm__ volatile("syscall" : "=a" (ret) :: "rcx", "r11");
	return ret;
}
char *getcwd(char *, size_t);
/*
static inline char* getcwd(char *buf, unsigned long size);
static inline char* getcwd(char *buf, unsigned long size)
{
	register char *_buf __asm__("rdi") = buf;
	register unsigned long _size __asm__("rsi") = size;
	__asm__("mov {%0, %%eax | eax, %0}" :: "i" (SYS_getcwd),  "r" (_buf), "r" (_size) : "eax");
	char* ret;
	__asm__ volatile("syscall" : "=a" (ret) :: "rcx", "r11");
	return ret;
}
*/
static inline gid_t getegid(void);
static inline gid_t getegid(void)
{
	__asm__("mov {%0, %%eax | eax, %0}" :: "i" (SYS_getegid) : "eax");
	gid_t ret;
	__asm__ volatile("syscall" : "=a" (ret) :: "rcx", "r11");
	return ret;
}

static inline uid_t geteuid(void);
static inline uid_t geteuid(void)
{
	__asm__("mov {%0, %%eax | eax, %0}" :: "i" (SYS_geteuid) : "eax");
	uid_t ret;
	__asm__ volatile("syscall" : "=a" (ret) :: "rcx", "r11");
	return ret;
}

static inline gid_t getgid(void);
static inline gid_t getgid(void)
{
	__asm__("mov {%0, %%eax | eax, %0}" :: "i" (SYS_getgid) : "eax");
	gid_t ret;
	__asm__ volatile("syscall" : "=a" (ret) :: "rcx", "r11");
	return ret;
}

static inline int getgroups(int gidsetsize, gid_t *grouplist);
static inline int getgroups(int gidsetsize, gid_t *grouplist)
{
	register int _gidsetsize __asm__("edi") = gidsetsize;
	register gid_t *_grouplist __asm__("rsi") = grouplist;
	__asm__("mov {%0, %%eax | eax, %0}" :: "i" (SYS_getgroups),  "r" (_gidsetsize), "r" (_grouplist) : "eax");
	int ret;
	__asm__ volatile("syscall" : "=a" (ret) :: "rcx", "r11");
	return ret;
}

static inline pid_t getpgid(pid_t pid);
static inline pid_t getpgid(pid_t pid)
{
	register pid_t _pid __asm__("rdi") = pid;
	__asm__("mov {%0, %%eax | eax, %0}" :: "i" (SYS_getpgid),  "r" (_pid) : "eax");
	pid_t ret;
	__asm__ volatile("syscall" : "=a" (ret) :: "rcx", "r11");
	return ret;
}

static inline pid_t getpgrp(void);
static inline pid_t getpgrp(void)
{
	return getpgid(0);
}

static inline pid_t getpid(void);
static inline pid_t getpid(void)
{
	__asm__("mov {%0, %%eax | eax, %0}" :: "i" (SYS_getpid) : "eax");
	pid_t ret;
	__asm__ volatile("syscall" : "=a" (ret) :: "rcx", "r11");
	return ret;
}

static inline pid_t getppid(void);
static inline pid_t getppid(void)
{
	__asm__("mov {%0, %%eax | eax, %0}" :: "i" (SYS_getppid) : "eax");
	pid_t ret;
	__asm__ volatile("syscall" : "=a" (ret) :: "rcx", "r11");
	return ret;
}

static inline pid_t getsid(pid_t pid);
static inline pid_t getsid(pid_t pid)
{
	register pid_t _pid __asm__("rdi") = pid;
	__asm__("mov {%0, %%eax | eax, %0}" :: "i" (SYS_getsid),  "r" (_pid) : "eax");
	pid_t ret;
	__asm__ volatile("syscall" : "=a" (ret) :: "rcx", "r11");
	return ret;
}

static inline uid_t getuid(void);
static inline uid_t getuid(void)
{
	__asm__("mov {%0, %%eax | eax, %0}" :: "i" (SYS_getuid) : "eax");
	uid_t ret;
	__asm__ volatile("syscall" : "=a" (ret) :: "rcx", "r11");
	return ret;
}

static inline int lchown(const char *filename, uid_t user, gid_t group);
static inline int lchown(const char *filename, uid_t user, gid_t group)
{
	register const char *_filename __asm__("rdi") = filename;
	register uid_t _user __asm__("esi") = user;
	register gid_t _group __asm__("edx") = group;
	__asm__("mov {%0, %%eax | eax, %0}" :: "i" (SYS_lchown),  "r" (_filename), "r" (_user), "r" (_group) : "eax");
	int ret;
	__asm__ volatile("syscall" : "=a" (ret) :: "rcx", "r11");
	return ret;
}

static inline int link(const char *oldname, const char *newname);
static inline int link(const char *oldname, const char *newname)
{
	register const char *_oldname __asm__("rdi") = oldname;
	register const char *_newname __asm__("rsi") = newname;
	__asm__("mov {%0, %%eax | eax, %0}" :: "i" (SYS_link),  "r" (_oldname), "r" (_newname) : "eax");
	int ret;
	__asm__ volatile("syscall" : "=a" (ret) :: "rcx", "r11");
	return ret;
}

static inline int linkat(int olddfd, const char *oldname, int newdfd, const char *newname, int flags);
static inline int linkat(int olddfd, const char *oldname, int newdfd, const char *newname, int flags)
{
	register int _olddfd __asm__("edi") = olddfd;
	register const char *_oldname __asm__("rsi") = oldname;
	register int _newdfd __asm__("edx") = newdfd;
	register const char *_newname __asm__("r8") = newname;
	register int _flags __asm__("r9d") = flags;
	__asm__("mov {%0, %%eax | eax, %0}" :: "i" (SYS_linkat),  "r" (_olddfd), "r" (_oldname), "r" (_newdfd), "r" (_newname), "r" (_flags) : "eax");
	int ret;
	__asm__ volatile("syscall" : "=a" (ret) :: "rcx", "r11");
	return ret;
}
off_t lseek(int, off_t, int);
/*
static inline off_t lseek(unsigned int fd, off_t offset, unsigned int whence);
static inline off_t lseek(unsigned int fd, off_t offset, unsigned int whence)
{
	register unsigned int _fd __asm__("edi") = fd;
	register off_t _offset __asm__("esi") = offset;
	register unsigned int _whence __asm__("edx") = whence;
	__asm__("mov {%0, %%eax | eax, %0}" :: "i" (SYS_lseek),  "r" (_fd), "r" (_offset), "r" (_whence) : "eax");
	off_t ret;
	__asm__ volatile("syscall" : "=a" (ret) :: "rcx", "r11");
	return ret;
}
*/
int pause(void);
/*
static inline int pause(void);
static inline int pause(void)
{
	__asm__("mov {%0, %%eax | eax, %0}" :: "i" (SYS_pause) : "eax");
	int ret;
	__asm__ volatile("syscall" : "=a" (ret) :: "rcx", "r11");
	return ret;
}
*/
static inline int pipe(int *fildes);
static inline int pipe(int *fildes)
{
	register int *_fildes __asm__("rdi") = fildes;
	__asm__("mov {%0, %%eax | eax, %0}" :: "i" (SYS_pipe),  "r" (_fildes) : "eax");
	int ret;
	__asm__ volatile("syscall" : "=a" (ret) :: "rcx", "r11");
	return ret;
}

static inline int pipe2(int *fildes, int flags);
static inline int pipe2(int *fildes, int flags)
{
	register int *_fildes __asm__("rdi") = fildes;
	register int _flags __asm__("rsi") = flags;
	__asm__("mov {%0, %%eax | eax, %0}" :: "i" (SYS_pipe),  "r" (_fildes), "r" (_flags)  : "eax");
	int ret;
	__asm__ volatile("syscall" : "=a" (ret) :: "rcx", "r11");
	return ret;
}
ssize_t read(int, void *, size_t);
/*
static inline ssize_t read(unsigned int fd, void *buf, size_t count);
static inline ssize_t read(unsigned int fd, void *buf, size_t count)
{
	register unsigned int _fd __asm__("edi") = fd;
	register char *_buf __asm__("rsi") = buf;
	register size_t _count __asm__("rdx") = count;
	__asm__("mov {%0, %%eax | eax, %0}" :: "i" (SYS_read),  "r" (_fd), "r" (_buf), "r" (_count) : "eax");
	ssize_t ret;
	__asm__ volatile("syscall" : "=a" (ret) :: "rcx", "r11");
	return ret;
}
*/
/* Another mismatched type with the linux kernel size_t -> int */
static inline ssize_t readlink(const char *path, char *buf, size_t bufsiz);
static inline ssize_t readlink(const char *path, char *buf, size_t bufsiz)
{
	register const char *_path __asm__("rdi") = path;
	register char *_buf __asm__("rsi") = buf;
	register size_t _bufsiz __asm__("edx") = bufsiz;
	__asm__("mov {%0, %%eax | eax, %0}" :: "i" (SYS_readlink),  "r" (_path), "r" (_buf), "r" (_bufsiz) : "eax");
	ssize_t ret;
	__asm__ volatile("syscall" : "=a" (ret) :: "rcx", "r11");
	return ret;
}
ssize_t readlinkat(int, const char *__restrict, char *__restrict, size_t);
/*
static inline ssize_t readlinkat(int dfd, const char *path, char *buf, int bufsiz);
static inline ssize_t readlinkat(int dfd, const char *path, char *buf, int bufsiz)
{
	register int _dfd __asm__("edi") = dfd;
	register const char *_path __asm__("rsi") = path;
	register char *_buf __asm__("rdx") = buf;
	register int _bufsiz __asm__("r8d") = bufsiz;
	__asm__("mov {%0, %%eax | eax, %0}" :: "i" (SYS_readlinkat),  "r" (_dfd), "r" (_path), "r" (_buf), "r" (_bufsiz) : "eax");
	ssize_t ret;
	__asm__ volatile("syscall" : "=a" (ret) :: "rcx", "r11");
	return ret;
}
*/

static inline int rmdir(const char *pathname);
static inline int rmdir(const char *pathname)
{
	register const char *_pathname __asm__("rdi") = pathname;
	__asm__("mov {%0, %%eax | eax, %0}" :: "i" (SYS_rmdir),  "r" (_pathname) : "eax");
	int ret;
	__asm__ volatile("syscall" : "=a" (ret) :: "rcx", "r11");
	return __syscall_ret(ret);

}
int setgid(gid_t);
/*
static inline int setgid(gid_t gid);
static inline int setgid(gid_t gid)
{
	register gid_t _gid __asm__("edi") = gid;
	__asm__("mov {%0, %%eax | eax, %0}" :: "i" (SYS_setgid),  "r" (_gid) : "eax");
	int ret;
	__asm__ volatile("syscall" : "=a" (ret) :: "rcx", "r11");
	return ret;
}
*/
static inline int setpgid(pid_t pid, pid_t pgid);
static inline int setpgid(pid_t pid, pid_t pgid)
{
	register pid_t _pid __asm__("rdi") = pid;
	register pid_t _pgid __asm__("rsi") = pgid;
	__asm__("mov {%0, %%eax | eax, %0}" :: "i" (SYS_setpgid),  "r" (_pid), "r" (_pgid) : "eax");
	int ret;
	__asm__ volatile("syscall" : "=a" (ret) :: "rcx", "r11");
	return ret;
}

static inline pid_t setpgrp(void);
static inline pid_t setpgrp(void)
{
	return setpgid(0, 0);
}

static inline pid_t setsid(void);
static inline pid_t setsid(void)
{
	__asm__("mov {%0, %%eax | eax, %0}" :: "i" (SYS_setsid) : "eax");
	pid_t ret;
	__asm__ volatile("syscall" : "=a" (ret) :: "rcx", "r11");
	return ret;
}
int setuid(uid_t);
/*
static inline int setuid(uid_t uid);
static inline int setuid(uid_t uid)
{
	register uid_t _uid __asm__("edi") = uid;
	__asm__("mov {%0, %%eax | eax, %0}" :: "i" (SYS_setuid),  "r" (_uid) : "eax");
	int ret;
	__asm__ volatile("syscall" : "=a" (ret) :: "rcx", "r11");
	return ret;
}
*/
static inline int symlink(const char *old, const char *_new);
static inline int symlink(const char *old, const char *_new)
{
	register const char *_old __asm__("rdi") = old;
	register const char *__new __asm__("rsi") = _new;
	__asm__("mov {%0, %%eax | eax, %0}" :: "i" (SYS_symlink),  "r" (_old), "r" (__new) : "eax");
	int ret;
	__asm__ volatile("syscall" : "=a" (ret) :: "rcx", "r11");
	return ret;
}

static inline int symlinkat(const char * oldname, int newdfd, const char * newname);
static inline int symlinkat(const char * oldname, int newdfd, const char * newname)
{
	register const char *_oldname __asm__("rdi") = oldname;
	register int _newdfd __asm__("esi") = newdfd;
	register const char *_newname __asm__("rdx") = newname;
	__asm__("mov {%0, %%eax | eax, %0}" :: "i" (SYS_symlinkat),  "r" (_oldname), "r" (_newdfd), "r" (_newname) : "eax");
	int ret;
	__asm__ volatile("syscall" : "=a" (ret) :: "rcx", "r11");
	return ret;
}

static inline int truncate(const char *path, long length);
static inline int truncate(const char *path, long length)
{
	register const char *_path __asm__("rdi") = path;
	register long _length __asm__("rsi") = length;
	__asm__("mov {%0, %%eax | eax, %0}" :: "i" (SYS_truncate),  "r" (_path), "r" (_length) : "eax");
	int ret;
	__asm__ volatile("syscall" : "=a" (ret) :: "rcx", "r11");
	return ret;
}

static inline int unlink(const char *pathname);
static inline int unlink(const char *pathname)
{
	register const char *_pathname __asm__("rdi") = pathname;
	__asm__("mov {%0, %%eax | eax, %0}" :: "i" (SYS_unlink),  "r" (_pathname) : "eax");
	int ret;
	__asm__ volatile("syscall" : "=a" (ret) :: "rcx", "r11");

	return __syscall_ret(ret);

}

static inline int unlinkat(int dfd, const char *pathname, int flag);
static inline int unlinkat(int dfd, const char *pathname, int flag)
{
	register int _dfd __asm__("edi") = dfd;
	register const char *_pathname __asm__("rsi") = pathname;
	register int _flag __asm__("edx") = flag;
	__asm__("mov {%0, %%eax | eax, %0}" :: "i" (SYS_unlinkat),  "r" (_dfd), "r" (_pathname), "r" (_flag) : "eax");
	int ret;
	__asm__ volatile("syscall" : "=a" (ret) :: "rcx", "r11");
	return ret;
}

static inline ssize_t write(int fd, const void *buf, size_t count);
static inline ssize_t write(int fd, const void *buf, size_t count)
{
	register int _fd __asm__("edi") = fd;
	register const void *_buf __asm__("rsi") = buf;
	register size_t _count __asm__("rdx") = count;
	__asm__("mov {%0, %%eax | eax, %0}" :: "i" (SYS_write),  "r" (_fd), "r" (_buf), "r" (_count) : "eax");
	ssize_t ret;
	__asm__ volatile("syscall" : "=a" (ret) :: "rcx", "r11");
	return __syscall_ret(ret);
}

/*
static inline ssize_t writev(int fd, const struct iovec *iov, size_t count);
static inline ssize_t writev(int fd, const struct iovec *iov, size_t count)
{
	register int _fd __asm__("edi") = fd;
	register const struct iovec *_iov __asm__("rsi") = iov;
	register size_t _count __asm__("rdx") = count;
	__asm__("mov {%0, %%eax | eax, %0}" :: "i" (SYS_writev),  "r" (_fd), "r" (_iov), "r" (_count) : "eax");
	ssize_t ret;
	__asm__ volatile("syscall" : "=a" (ret) :: "rcx", "r11");
	return ret;
}
*/

int posix_close(int, int);
ssize_t pread(int, void *, size_t, off_t);
ssize_t pwrite(int, const void *, size_t, off_t);
unsigned sleep(unsigned);
pid_t _Fork(void);


int execv(const char *, char *const []);
int execle(const char *, const char *, ...);
int execl(const char *, const char *, ...);
int execvp(const char *, char *const []);
int execlp(const char *, const char *, ...);
int fexecve(int, char *const [], char *const []);
_Noreturn void _exit(int);

char *ttyname(int);
int ttyname_r(int, char *, size_t);
int isatty(int);
pid_t tcgetpgrp(int);
int tcsetpgrp(int, pid_t);

int seteuid(uid_t);
int setegid(gid_t);

char *getlogin(void);
int getlogin_r(char *, size_t);
int gethostname(char *, size_t);
char *ctermid(char *);

int getopt(int, char * const [], const char *);
extern char *optarg;
extern int optind, opterr, optopt;

long pathconf(const char *, int);
long fpathconf(int, int);
long sysconf(int);
size_t confstr(int, char *, size_t);

#if defined(_XOPEN_SOURCE) || defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
#define F_ULOCK 0
#define F_LOCK  1
#define F_TLOCK 2
#define F_TEST  3
int setreuid(uid_t, uid_t);
/*
static inline int setreuid(uid_t ruid, uid_t euid);
static inline int setreuid(uid_t ruid, uid_t euid)
{
	register uid_t _ruid __asm__("edi") = ruid;
	register uid_t _euid __asm__("esi") = euid;
	__asm__("mov {%0, %%eax | eax, %0}" :: "i" (SYS_setreuid),  "r" (_ruid), "r" (_euid) : "eax");
	int ret;
	__asm__ volatile("syscall" : "=a" (ret) :: "rcx", "r11");
	return ret;
}
*/
int setregid(gid_t, gid_t);
/*
static inline int setregid(gid_t rgid, gid_t egid);
static inline int setregid(gid_t rgid, gid_t egid)
{
	register gid_t _rgid __asm__("edi") = rgid;
	register gid_t _egid __asm__("esi") = egid;
	__asm__("mov {%0, %%eax | eax, %0}" :: "i" (SYS_setregid),  "r" (_rgid), "r" (_egid) : "eax");
	int ret;
	__asm__ volatile("syscall" : "=a" (ret) :: "rcx", "r11");
	return ret;
}
*/
static inline void sync(void);
static inline void sync(void)
{
	__asm__("mov {%0, %%eax | eax, %0}" :: "i" (SYS_sync) : "eax");
	__asm__ volatile("syscall" ::: "rcx", "r11");
}

int lockf(int, int, off_t);
long gethostid(void);
int nice(int);
pid_t setpgrp(void);
char *crypt(const char *, const char *);
void encrypt(char *, int);
void swab(const void *__restrict, void *__restrict, ssize_t);
#endif

#if defined(_GNU_SOURCE) || defined(_BSD_SOURCE) \
 || (defined(_XOPEN_SOURCE) && _XOPEN_SOURCE+0 < 700)
int usleep(unsigned);
unsigned ualarm(unsigned, unsigned);
#endif

#if defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
#define L_SET 0
#define L_INCR 1
#define L_XTND 2
int brk(void *);
void *sbrk(intptr_t);
pid_t vfork(void);
int vhangup(void);
int chroot(const char *);
int getpagesize(void);
int getdtablesize(void);
int sethostname(const char *, size_t);
int getdomainname(char *, size_t);
int setdomainname(const char *, size_t);
int setgroups(size_t, const gid_t *);
char *getpass(const char *);
int daemon(int, int);
void setusershell(void);
void endusershell(void);
char *getusershell(void);

static inline int chdir(const char *filename);
static inline int chdir(const char *filename)
{
	register const char *_filename __asm__("rdi") = filename;
	__asm__("mov {%0, %%eax | eax, %0}" :: "i" (SYS_acct),  "r" (_filename) : "eax");
	int ret;
	__asm__ volatile("syscall" : "=a" (ret) :: "rcx", "r11");
	return ret;
}

long syscall(long, ...);
int execvpe(const char *, char *const [], char *const []);
int issetugid(void);
int getentropy(void *, size_t);
extern int optreset;
#endif

#ifdef _GNU_SOURCE
extern char **environ;
int setresuid(uid_t, uid_t, uid_t);
int setresgid(gid_t, gid_t, gid_t);
int getresuid(uid_t *, uid_t *, uid_t *);
int getresgid(gid_t *, gid_t *, gid_t *);
char *get_current_dir_name(void);
int syncfs(int);
int euidaccess(const char *, int);
int eaccess(const char *, int);
ssize_t copy_file_range(int, off_t *, int, off_t *, size_t, unsigned);
pid_t gettid(void);
#endif

#if defined(_LARGEFILE64_SOURCE)
#define lseek64 lseek
#define pread64 pread
#define pwrite64 pwrite
#define truncate64 truncate
#define ftruncate64 ftruncate
#define lockf64 lockf
#define off64_t off_t
#endif

#define POSIX_CLOSE_RESTART			0

#define _XOPEN_VERSION				700
#define _XOPEN_UNIX				1
#define _XOPEN_ENH_I18N				1

#define _POSIX_VERSION				200809L
#define _POSIX2_VERSION				_POSIX_VERSION

#define _POSIX_ADVISORY_INFO			_POSIX_VERSION
#define _POSIX_CHOWN_RESTRICTED			1
#define _POSIX_IPV6				_POSIX_VERSION
#define _POSIX_JOB_CONTROL			1
#define _POSIX_MAPPED_FILES			_POSIX_VERSION
#define _POSIX_MEMLOCK				_POSIX_VERSION
#define _POSIX_MEMLOCK_RANGE			_POSIX_VERSION
#define _POSIX_MEMORY_PROTECTION		_POSIX_VERSION
#define _POSIX_MESSAGE_PASSING			_POSIX_VERSION
#define _POSIX_FSYNC				_POSIX_VERSION
#define _POSIX_NO_TRUNC				1
#define _POSIX_RAW_SOCKETS			_POSIX_VERSION
#define _POSIX_REALTIME_SIGNALS			_POSIX_VERSION
#define _POSIX_REGEXP				1
#define _POSIX_SAVED_IDS			1
#define _POSIX_SHELL				1
#define _POSIX_SPAWN				_POSIX_VERSION
#define _POSIX_VDISABLE				0

#define _POSIX_THREADS				_POSIX_VERSION
#define _POSIX_THREAD_PROCESS_SHARED		_POSIX_VERSION
#define _POSIX_THREAD_SAFE_FUNCTIONS		_POSIX_VERSION
#define _POSIX_THREAD_ATTR_STACKADDR		_POSIX_VERSION
#define _POSIX_THREAD_ATTR_STACKSIZE		_POSIX_VERSION
#define _POSIX_THREAD_PRIORITY_SCHEDULING	_POSIX_VERSION
#define _POSIX_THREAD_CPUTIME			_POSIX_VERSION
#define _POSIX_TIMERS				_POSIX_VERSION
#define _POSIX_TIMEOUTS				_POSIX_VERSION
#define _POSIX_MONOTONIC_CLOCK			_POSIX_VERSION
#define _POSIX_CPUTIME				_POSIX_VERSION
#define _POSIX_CLOCK_SELECTION			_POSIX_VERSION
#define _POSIX_BARRIERS				_POSIX_VERSION
#define _POSIX_SPIN_LOCKS			_POSIX_VERSION
#define _POSIX_READER_WRITER_LOCKS		_POSIX_VERSION
#define _POSIX_ASYNCHRONOUS_IO			_POSIX_VERSION
#define _POSIX_SEMAPHORES			_POSIX_VERSION
#define _POSIX_SHARED_MEMORY_OBJECTS		_POSIX_VERSION

#define _POSIX2_C_BIND				_POSIX_VERSION

#if __LONG_MAX == 0x7fffffffL
#define _POSIX_V6_ILP32_OFFBIG			1
#define _POSIX_V7_ILP32_OFFBIG			1
#else
#define _POSIX_V6_LP64_OFF64			1
#define _POSIX_V7_LP64_OFF64			1
#endif



#define _PC_LINK_MAX				0
#define _PC_MAX_CANON				1
#define _PC_MAX_INPUT				2
#define _PC_NAME_MAX				3
#define _PC_PATH_MAX				4
#define _PC_PIPE_BUF				5
#define _PC_CHOWN_RESTRICTED			6
#define _PC_NO_TRUNC				7
#define _PC_VDISABLE				8
#define _PC_SYNC_IO				9
#define _PC_ASYNC_IO				10
#define _PC_PRIO_IO				11
#define _PC_SOCK_MAXBUF				12
#define _PC_FILESIZEBITS			13
#define _PC_REC_INCR_XFER_SIZE			14
#define _PC_REC_MAX_XFER_SIZE			15
#define _PC_REC_MIN_XFER_SIZE			16
#define _PC_REC_XFER_ALIGN			17
#define _PC_ALLOC_SIZE_MIN			18
#define _PC_SYMLINK_MAX				19
#define _PC_2_SYMLINKS				20

#define _SC_ARG_MAX				0
#define _SC_CHILD_MAX				1
#define _SC_CLK_TCK				2
#define _SC_NGROUPS_MAX				3
#define _SC_OPEN_MAX				4
#define _SC_STREAM_MAX				5
#define _SC_TZNAME_MAX				6
#define _SC_JOB_CONTROL				7
#define _SC_SAVED_IDS				8
#define _SC_REALTIME_SIGNALS			9
#define _SC_PRIORITY_SCHEDULING			10
#define _SC_TIMERS				11
#define _SC_ASYNCHRONOUS_IO			12
#define _SC_PRIORITIZED_IO			13
#define _SC_SYNCHRONIZED_IO			14
#define _SC_FSYNC				15
#define _SC_MAPPED_FILES			16
#define _SC_MEMLOCK				17
#define _SC_MEMLOCK_RANGE			18
#define _SC_MEMORY_PROTECTION			19
#define _SC_MESSAGE_PASSING			20
#define _SC_SEMAPHORES				21
#define _SC_SHARED_MEMORY_OBJECTS		22
#define _SC_AIO_LISTIO_MAX			23
#define _SC_AIO_MAX				24
#define _SC_AIO_PRIO_DELTA_MAX			25
#define _SC_DELAYTIMER_MAX			26
#define _SC_MQ_OPEN_MAX				27
#define _SC_MQ_PRIO_MAX				28
#define _SC_VERSION				29

#define _SC_PAGE_SIZE				30
#define _SC_PAGESIZE				30

#define _SC_RTSIG_MAX				31
#define _SC_SEM_NSEMS_MAX			32
#define _SC_SEM_VALUE_MAX			33
#define _SC_SIGQUEUE_MAX			34
#define _SC_TIMER_MAX				35
#define _SC_BC_BASE_MAX				36
#define _SC_BC_DIM_MAX				37
#define _SC_BC_SCALE_MAX			38
#define _SC_BC_STRING_MAX			39
#define _SC_COLL_WEIGHTS_MAX			40
#define _SC_EXPR_NEST_MAX			42
#define _SC_LINE_MAX				43
#define _SC_RE_DUP_MAX				44
#define _SC_2_VERSION				46
#define _SC_2_C_BIND				47
#define _SC_2_C_DEV				48
#define _SC_2_FORT_DEV				49
#define _SC_2_FORT_RUN				50
#define _SC_2_SW_DEV				51
#define _SC_2_LOCALEDEF				52

#define _SC_UIO_MAXIOV				60
#define _SC_IOV_MAX				60

#define _SC_THREADS				67
#define _SC_THREAD_SAFE_FUNCTIONS		68
#define _SC_GETGR_R_SIZE_MAX			69
#define _SC_GETPW_R_SIZE_MAX			70
#define _SC_LOGIN_NAME_MAX			71
#define _SC_TTY_NAME_MAX			72
#define _SC_THREAD_DESTRUCTOR_ITERATIONS	73
#define _SC_THREAD_KEYS_MAX			74
#define _SC_THREAD_STACK_MIN			75
#define _SC_THREAD_THREADS_MAX			76
#define _SC_THREAD_ATTR_STACKADDR		77
#define _SC_THREAD_ATTR_STACKSIZE		78
#define _SC_THREAD_PRIORITY_SCHEDULING		79
#define _SC_THREAD_PRIO_INHERIT			80
#define _SC_THREAD_PRIO_PROTECT			81
#define _SC_THREAD_PROCESS_SHARED		82
#define _SC_NPROCESSORS_CONF			83
#define _SC_NPROCESSORS_ONLN			84
#define _SC_PHYS_PAGES				85
#define _SC_AVPHYS_PAGES			86
#define _SC_ATEXIT_MAX				87
#define _SC_PASS_MAX				88
#define _SC_XOPEN_VERSION			89
#define _SC_XOPEN_XCU_VERSION			90
#define _SC_XOPEN_UNIX				91
#define _SC_XOPEN_CRYPT				92
#define _SC_XOPEN_ENH_I18N			93
#define _SC_XOPEN_SHM				94
#define _SC_2_CHAR_TERM				95
#define _SC_2_UPE				97
#define _SC_XOPEN_XPG2				98
#define _SC_XOPEN_XPG3				99
#define _SC_XOPEN_XPG4				100
#define _SC_NZERO				109
#define _SC_XBS5_ILP32_OFF32			125
#define _SC_XBS5_ILP32_OFFBIG			126
#define _SC_XBS5_LP64_OFF64			127
#define _SC_XBS5_LPBIG_OFFBIG			128
#define _SC_XOPEN_LEGACY			129
#define _SC_XOPEN_REALTIME			130
#define _SC_XOPEN_REALTIME_THREADS		131
#define _SC_ADVISORY_INFO			132
#define _SC_BARRIERS				133
#define _SC_CLOCK_SELECTION			137
#define _SC_CPUTIME				138
#define _SC_THREAD_CPUTIME			139
#define _SC_MONOTONIC_CLOCK			149
#define _SC_READER_WRITER_LOCKS			153
#define _SC_SPIN_LOCKS				154
#define _SC_REGEXP				155
#define _SC_SHELL				157
#define _SC_SPAWN				159
#define _SC_SPORADIC_SERVER			160
#define _SC_THREAD_SPORADIC_SERVER		161
#define _SC_TIMEOUTS				164
#define _SC_TYPED_MEMORY_OBJECTS		165
#define _SC_2_PBS				168
#define _SC_2_PBS_ACCOUNTING			169
#define _SC_2_PBS_LOCATE			170
#define _SC_2_PBS_MESSAGE			171
#define _SC_2_PBS_TRACK				172
#define _SC_SYMLOOP_MAX				173
#define _SC_STREAMS				174
#define _SC_2_PBS_CHECKPOINT			175
#define _SC_V6_ILP32_OFF32			176
#define _SC_V6_ILP32_OFFBIG			177
#define _SC_V6_LP64_OFF64			178
#define _SC_V6_LPBIG_OFFBIG			179
#define _SC_HOST_NAME_MAX			180
#define _SC_TRACE				181
#define _SC_TRACE_EVENT_FILTER			182
#define _SC_TRACE_INHERIT			183
#define _SC_TRACE_LOG				184

#define _SC_IPV6				235
#define _SC_RAW_SOCKETS				236
#define _SC_V7_ILP32_OFF32			237
#define _SC_V7_ILP32_OFFBIG			238
#define _SC_V7_LP64_OFF64			239
#define _SC_V7_LPBIG_OFFBIG			240
#define _SC_SS_REPL_MAX				241
#define _SC_TRACE_EVENT_NAME_MAX		242
#define _SC_TRACE_NAME_MAX			243
#define _SC_TRACE_SYS_MAX			244
#define _SC_TRACE_USER_EVENT_MAX		245
#define _SC_XOPEN_STREAMS			246
#define _SC_THREAD_ROBUST_PRIO_INHERIT		247
#define _SC_THREAD_ROBUST_PRIO_PROTECT		248
#define _SC_MINSIGSTKSZ				249
#define _SC_SIGSTKSZ				250

#define _CS_PATH				0
#define _CS_POSIX_V6_WIDTH_RESTRICTED_ENVS	1
#define _CS_GNU_LIBC_VERSION			2
#define _CS_GNU_LIBPTHREAD_VERSION		3
#define _CS_POSIX_V5_WIDTH_RESTRICTED_ENVS	4
#define _CS_POSIX_V7_WIDTH_RESTRICTED_ENVS	5

#define _CS_POSIX_V6_ILP32_OFF32_CFLAGS		1116
#define _CS_POSIX_V6_ILP32_OFF32_LDFLAGS	1117
#define _CS_POSIX_V6_ILP32_OFF32_LIBS		1118
#define _CS_POSIX_V6_ILP32_OFF32_LINTFLAGS	1119
#define _CS_POSIX_V6_ILP32_OFFBIG_CFLAGS	1120
#define _CS_POSIX_V6_ILP32_OFFBIG_LDFLAGS	1121
#define _CS_POSIX_V6_ILP32_OFFBIG_LIBS		1122
#define _CS_POSIX_V6_ILP32_OFFBIG_LINTFLAGS	1123
#define _CS_POSIX_V6_LP64_OFF64_CFLAGS		1124
#define _CS_POSIX_V6_LP64_OFF64_LDFLAGS		1125
#define _CS_POSIX_V6_LP64_OFF64_LIBS		1126
#define _CS_POSIX_V6_LP64_OFF64_LINTFLAGS	1127
#define _CS_POSIX_V6_LPBIG_OFFBIG_CFLAGS	1128
#define _CS_POSIX_V6_LPBIG_OFFBIG_LDFLAGS	1129
#define _CS_POSIX_V6_LPBIG_OFFBIG_LIBS		1130
#define _CS_POSIX_V6_LPBIG_OFFBIG_LINTFLAGS	1131
#define _CS_POSIX_V7_ILP32_OFF32_CFLAGS		1132
#define _CS_POSIX_V7_ILP32_OFF32_LDFLAGS	1133
#define _CS_POSIX_V7_ILP32_OFF32_LIBS		1134
#define _CS_POSIX_V7_ILP32_OFF32_LINTFLAGS	1135
#define _CS_POSIX_V7_ILP32_OFFBIG_CFLAGS	1136
#define _CS_POSIX_V7_ILP32_OFFBIG_LDFLAGS	1137
#define _CS_POSIX_V7_ILP32_OFFBIG_LIBS		1138
#define _CS_POSIX_V7_ILP32_OFFBIG_LINTFLAGS	1139
#define _CS_POSIX_V7_LP64_OFF64_CFLAGS		1140
#define _CS_POSIX_V7_LP64_OFF64_LDFLAGS		1141
#define _CS_POSIX_V7_LP64_OFF64_LIBS		1142
#define _CS_POSIX_V7_LP64_OFF64_LINTFLAGS	1143
#define _CS_POSIX_V7_LPBIG_OFFBIG_CFLAGS	1144
#define _CS_POSIX_V7_LPBIG_OFFBIG_LDFLAGS	1145
#define _CS_POSIX_V7_LPBIG_OFFBIG_LIBS		1146
#define _CS_POSIX_V7_LPBIG_OFFBIG_LINTFLAGS	1147
#define _CS_V6_ENV				1148
#define _CS_V7_ENV				1149
#define _CS_POSIX_V7_THREADS_CFLAGS		1150
#define _CS_POSIX_V7_THREADS_LDFLAGS		1151


#ifdef __cplusplus
}
#endif

#endif
