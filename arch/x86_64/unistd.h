static inline int access(const char *filename, int mode);
static inline int access(const char *filename, int mode)
{
	register const char *_filename asm("rdi") = filename;
	register int _mode asm("esi") = mode;
	asm("mov {%0, %%eax | eax, %0}" :: "i" (SYS_access),  "r" (_filename), "r" (_mode) : "eax");
	int ret;
	asm volatile("syscall" : "=a" (ret) :: "rcx", "r11");
	return ret;
}

static inline unsigned int alarm(unsigned int seconds);
static inline unsigned int alarm(unsigned int seconds)
{
	register unsigned int _seconds asm("edi") = seconds;
	asm("mov {%0, %%eax | eax, %0}" :: "i" (SYS_alarm),  "r" (_seconds) : "eax");
	unsigned int ret;
	asm volatile("syscall" : "=a" (ret) :: "rcx", "r11");
	return ret;
}

static inline int chdir(const char *filename);
static inline int chdir(const char *filename)
{
	register const char *_filename asm("rdi") = filename;
	asm("mov {%0, %%eax | eax, %0}" :: "i" (SYS_chdir),  "r" (_filename) : "eax");
	int ret;
	asm volatile("syscall" : "=a" (ret) :: "rcx", "r11");
	return ret;
}

static inline int chown(const char *filename, uid_t user, gid_t group);
static inline int chown(const char *filename, uid_t user, gid_t group)
{
	register const char *_filename asm("rdi") = filename;
	register uid_t _user asm("esi") = user;
	register gid_t _group asm("edx") = group;
	asm("mov {%0, %%eax | eax, %0}" :: "i" (SYS_chown),  "r" (_filename), "r" (_user), "r" (_group) : "eax");
	int ret;
	asm volatile("syscall" : "=a" (ret) :: "rcx", "r11");
	return ret;
}

static inline int close(unsigned int fd);
static inline int close(unsigned int fd)
{
	register unsigned int _fd asm("edi") = fd;
	asm("mov {%0, %%eax | eax, %0}" :: "i" (SYS_close),  "r" (_fd) : "eax");
	int ret;
	asm volatile("syscall" : "=a" (ret) :: "rcx", "r11");
	return ret;
}

static inline int dup(unsigned int fildes);
static inline int dup(unsigned int fildes)
{
	register unsigned int _fildes asm("edi") = fildes;
	asm("mov {%0, %%eax | eax, %0}" :: "i" (SYS_dup),  "r" (_fildes) : "eax");
	int ret;
	asm volatile("syscall" : "=a" (ret) :: "rcx", "r11");
	return ret;
}

static inline int dup2(unsigned int oldfd, unsigned int newfd);
static inline int dup2(unsigned int oldfd, unsigned int newfd)
{
	register unsigned int _oldfd asm("edi") = oldfd;
	register unsigned int _newfd asm("esi") = newfd;
	asm("mov {%0, %%eax | eax, %0}" :: "i" (SYS_dup2),  "r" (_oldfd), "r" (_newfd) : "eax");
	int ret;
	asm volatile("syscall" : "=a" (ret) :: "rcx", "r11");
	return ret;
}

static inline int dup3(unsigned int oldfd, unsigned int newfd, int flags);
static inline int dup3(unsigned int oldfd, unsigned int newfd, int flags)
{
	register unsigned int _oldfd asm("edi") = oldfd;
	register unsigned int _newfd asm("esi") = newfd;
	register int _flags asm("edx") = flags;
	asm("mov {%0, %%eax | eax, %0}" :: "i" (SYS_dup3),  "r" (_oldfd), "r" (_newfd), "r" (_flags) : "eax");
	int ret;
	asm volatile("syscall" : "=a" (ret) :: "rcx", "r11");
	return ret;
}

static inline int execve(const char *filename, const char *const *argv, const char *const *envp);
static inline int execve(const char *filename, const char *const *argv, const char *const *envp)
{
	register const char *_filename asm("rdi") = filename;
	register const char *const *_argv asm("rsi") = argv;
	register const char *const *_envp asm("rdx") = envp;
	asm("mov {%0, %%eax | eax, %0}" :: "i" (SYS_execve),  "r" (_filename), "r" (_argv), "r" (_envp) : "eax");
	int ret;
	asm volatile("syscall" : "=a" (ret) :: "rcx", "r11");
	return ret;
}

static inline int faccessat(int dfd, const char *filename, int mode);
static inline int faccessat(int dfd, const char *filename, int mode)
{
	register int _dfd asm("edi") = dfd;
	register const char *_filename asm("rsi") = filename;
	register int _mode asm("edx") = mode;
	asm("mov {%0, %%eax | eax, %0}" :: "i" (SYS_faccessat),  "r" (_dfd), "r" (_filename), "r" (_mode) : "eax");
	int ret;
	asm volatile("syscall" : "=a" (ret) :: "rcx", "r11");
	return ret;
}

static inline int fchdir(unsigned int fd);
static inline int fchdir(unsigned int fd)
{
	register unsigned int _fd asm("edi") = fd;
	asm("mov {%0, %%eax | eax, %0}" :: "i" (SYS_fchdir),  "r" (_fd) : "eax");
	int ret;
	asm volatile("syscall" : "=a" (ret) :: "rcx", "r11");
	return ret;
}

static inline int fchown(unsigned int fd, uid_t user, gid_t group);
static inline int fchown(unsigned int fd, uid_t user, gid_t group)
{
	register unsigned int _fd asm("edi") = fd;
	register uid_t _user asm("esi") = user;
	register gid_t _group asm("edx") = group;
	asm("mov {%0, %%eax | eax, %0}" :: "i" (SYS_fchown),  "r" (_fd), "r" (_user), "r" (_group) : "eax");
	int ret;
	asm volatile("syscall" : "=a" (ret) :: "rcx", "r11");
	return ret;
}

static inline int fchownat(int dfd, const char *filename, uid_t user, gid_t group, int flag);
static inline int fchownat(int dfd, const char *filename, uid_t user, gid_t group, int flag)
{
	register int _dfd asm("edi") = dfd;
	register const char *_filename asm("rsi") = filename;
	register uid_t _user asm("edx") = user;
	register gid_t _group asm("r8d") = group;
	register int _flag asm("r9d") = flag;
	asm("mov {%0, %%eax | eax, %0}" :: "i" (SYS_fchownat),  "r" (_dfd), "r" (_filename), "r" (_user), "r" (_group), "r" (_flag) : "eax");
	int ret;
	asm volatile("syscall" : "=a" (ret) :: "rcx", "r11");
	return ret;
}

static inline int fdatasync(unsigned int fd);
static inline int fdatasync(unsigned int fd)
{
	register unsigned int _fd asm("edi") = fd;
	asm("mov {%0, %%eax | eax, %0}" :: "i" (SYS_fdatasync),  "r" (_fd) : "eax");
	int ret;
	asm volatile("syscall" : "=a" (ret) :: "rcx", "r11");
	return ret;
}

static inline int fork(void);
static inline int fork(void)
{
	asm("mov {%0, %%eax | eax, %0}" :: "i" (SYS_fork) : "eax");
	int ret;
	asm volatile("syscall" : "=a" (ret) :: "rcx", "r11");
	return ret;
}

static inline int fsync(unsigned int fd);
static inline int fsync(unsigned int fd)
{
	register unsigned int _fd asm("edi") = fd;
	asm("mov {%0, %%eax | eax, %0}" :: "i" (SYS_fsync),  "r" (_fd) : "eax");
	int ret;
	asm volatile("syscall" : "=a" (ret) :: "rcx", "r11");
	return ret;
}

static inline int ftruncate(unsigned int fd, off_t length);
static inline int ftruncate(unsigned int fd, off_t length)
{
	register unsigned int _fd asm("edi") = fd;
	register off_t _length asm("esi") = length;
	asm("mov {%0, %%eax | eax, %0}" :: "i" (SYS_ftruncate),  "r" (_fd), "r" (_length) : "eax");
	int ret;
	asm volatile("syscall" : "=a" (ret) :: "rcx", "r11");
	return ret;
}

static inline char* getcwd(char *buf, unsigned long size);
static inline char* getcwd(char *buf, unsigned long size)
{
	register char *_buf asm("rdi") = buf;
	register unsigned long _size asm("rsi") = size;
	asm("mov {%0, %%eax | eax, %0}" :: "i" (SYS_getcwd),  "r" (_buf), "r" (_size) : "eax");
	char* ret;
	asm volatile("syscall" : "=a" (ret) :: "rcx", "r11");
	return ret;
}

static inline gid_t getegid(void);
static inline gid_t getegid(void)
{
	asm("mov {%0, %%eax | eax, %0}" :: "i" (SYS_getegid) : "eax");
	gid_t ret;
	asm volatile("syscall" : "=a" (ret) :: "rcx", "r11");
	return ret;
}

static inline uid_t geteuid(void);
static inline uid_t geteuid(void)
{
	asm("mov {%0, %%eax | eax, %0}" :: "i" (SYS_geteuid) : "eax");
	uid_t ret;
	asm volatile("syscall" : "=a" (ret) :: "rcx", "r11");
	return ret;
}

static inline gid_t getgid(void);
static inline gid_t getgid(void)
{
	asm("mov {%0, %%eax | eax, %0}" :: "i" (SYS_getgid) : "eax");
	gid_t ret;
	asm volatile("syscall" : "=a" (ret) :: "rcx", "r11");
	return ret;
}

static inline int getgroups(int gidsetsize, gid_t *grouplist);
static inline int getgroups(int gidsetsize, gid_t *grouplist)
{
	register int _gidsetsize asm("edi") = gidsetsize;
	register gid_t *_grouplist asm("rsi") = grouplist;
	asm("mov {%0, %%eax | eax, %0}" :: "i" (SYS_getgroups),  "r" (_gidsetsize), "r" (_grouplist) : "eax");
	int ret;
	asm volatile("syscall" : "=a" (ret) :: "rcx", "r11");
	return ret;
}

static inline pid_t getpgid(pid_t pid);
static inline pid_t getpgid(pid_t pid)
{
	register pid_t _pid asm("rdi") = pid;
	asm("mov {%0, %%eax | eax, %0}" :: "i" (SYS_getpgid),  "r" (_pid) : "eax");
	pid_t ret;
	asm volatile("syscall" : "=a" (ret) :: "rcx", "r11");
	return ret;
}

static inline pid_t getsid(pid_t pid);
static inline pid_t getsid(pid_t pid)
{
	register pid_t _pid asm("rdi") = pid;
	asm("mov {%0, %%eax | eax, %0}" :: "i" (SYS_getsid),  "r" (_pid) : "eax");
	pid_t ret;
	asm volatile("syscall" : "=a" (ret) :: "rcx", "r11");
	return ret;
}

static inline uid_t getuid(void);
static inline uid_t getuid(void)
{
	asm("mov {%0, %%eax | eax, %0}" :: "i" (SYS_getuid) : "eax");
	uid_t ret;
	asm volatile("syscall" : "=a" (ret) :: "rcx", "r11");
	return ret;
}

static inline int lchown(const char *filename, uid_t user, gid_t group);
static inline int lchown(const char *filename, uid_t user, gid_t group)
{
	register const char *_filename asm("rdi") = filename;
	register uid_t _user asm("esi") = user;
	register gid_t _group asm("edx") = group;
	asm("mov {%0, %%eax | eax, %0}" :: "i" (SYS_lchown),  "r" (_filename), "r" (_user), "r" (_group) : "eax");
	int ret;
	asm volatile("syscall" : "=a" (ret) :: "rcx", "r11");
	return ret;
}

static inline int link(const char *oldname, const char *newname);
static inline int link(const char *oldname, const char *newname)
{
	register const char *_oldname asm("rdi") = oldname;
	register const char *_newname asm("rsi") = newname;
	asm("mov {%0, %%eax | eax, %0}" :: "i" (SYS_link),  "r" (_oldname), "r" (_newname) : "eax");
	int ret;
	asm volatile("syscall" : "=a" (ret) :: "rcx", "r11");
	return ret;
}

static inline int linkat(int olddfd, const char *oldname, int newdfd, const char *newname, int flags);
static inline int linkat(int olddfd, const char *oldname, int newdfd, const char *newname, int flags)
{
	register int _olddfd asm("edi") = olddfd;
	register const char *_oldname asm("rsi") = oldname;
	register int _newdfd asm("edx") = newdfd;
	register const char *_newname asm("r8") = newname;
	register int _flags asm("r9d") = flags;
	asm("mov {%0, %%eax | eax, %0}" :: "i" (SYS_linkat),  "r" (_olddfd), "r" (_oldname), "r" (_newdfd), "r" (_newname), "r" (_flags) : "eax");
	int ret;
	asm volatile("syscall" : "=a" (ret) :: "rcx", "r11");
	return ret;
}

static inline off_t lseek(unsigned int fd, off_t offset, unsigned int whence);
static inline off_t lseek(unsigned int fd, off_t offset, unsigned int whence)
{
	register unsigned int _fd asm("edi") = fd;
	register off_t _offset asm("esi") = offset;
	register unsigned int _whence asm("edx") = whence;
	asm("mov {%0, %%eax | eax, %0}" :: "i" (SYS_lseek),  "r" (_fd), "r" (_offset), "r" (_whence) : "eax");
	off_t ret;
	asm volatile("syscall" : "=a" (ret) :: "rcx", "r11");
	return ret;
}

static inline int pause(void);
static inline int pause(void)
{
	asm("mov {%0, %%eax | eax, %0}" :: "i" (SYS_pause) : "eax");
	int ret;
	asm volatile("syscall" : "=a" (ret) :: "rcx", "r11");
	return ret;
}

static inline int pipe(int *fildes);
static inline int pipe(int *fildes)
{
	register int *_fildes asm("rdi") = fildes;
	asm("mov {%0, %%eax | eax, %0}" :: "i" (SYS_pipe),  "r" (_fildes) : "eax");
	int ret;
	asm volatile("syscall" : "=a" (ret) :: "rcx", "r11");
	return ret;
}

static inline ssize_t read(unsigned int fd, char *buf, size_t count);
static inline ssize_t read(unsigned int fd, char *buf, size_t count)
{
	register unsigned int _fd asm("edi") = fd;
	register char *_buf asm("rsi") = buf;
	register size_t _count asm("rdx") = count;
	asm("mov {%0, %%eax | eax, %0}" :: "i" (SYS_read),  "r" (_fd), "r" (_buf), "r" (_count) : "eax");
	ssize_t ret;
	asm volatile("syscall" : "=a" (ret) :: "rcx", "r11");
	return ret;
}

static inline ssize_t readlink(const char *path, char *buf, int bufsiz);
static inline ssize_t readlink(const char *path, char *buf, int bufsiz)
{
	register const char *_path asm("rdi") = path;
	register char *_buf asm("rsi") = buf;
	register int _bufsiz asm("edx") = bufsiz;
	asm("mov {%0, %%eax | eax, %0}" :: "i" (SYS_readlink),  "r" (_path), "r" (_buf), "r" (_bufsiz) : "eax");
	ssize_t ret;
	asm volatile("syscall" : "=a" (ret) :: "rcx", "r11");
	return ret;
}

static inline ssize_t readlinkat(int dfd, const char *path, char *buf, int bufsiz);
static inline ssize_t readlinkat(int dfd, const char *path, char *buf, int bufsiz)
{
	register int _dfd asm("edi") = dfd;
	register const char *_path asm("rsi") = path;
	register char *_buf asm("rdx") = buf;
	register int _bufsiz asm("r8d") = bufsiz;
	asm("mov {%0, %%eax | eax, %0}" :: "i" (SYS_readlinkat),  "r" (_dfd), "r" (_path), "r" (_buf), "r" (_bufsiz) : "eax");
	ssize_t ret;
	asm volatile("syscall" : "=a" (ret) :: "rcx", "r11");
	return ret;
}

static inline int rmdir(const char *pathname);
static inline int rmdir(const char *pathname)
{
	register const char *_pathname asm("rdi") = pathname;
	asm("mov {%0, %%eax | eax, %0}" :: "i" (SYS_rmdir),  "r" (_pathname) : "eax");
	int ret;
	asm volatile("syscall" : "=a" (ret) :: "rcx", "r11");
	return ret;
}

static inline int setgid(gid_t gid);
static inline int setgid(gid_t gid)
{
	register gid_t _gid asm("edi") = gid;
	asm("mov {%0, %%eax | eax, %0}" :: "i" (SYS_setgid),  "r" (_gid) : "eax");
	int ret;
	asm volatile("syscall" : "=a" (ret) :: "rcx", "r11");
	return ret;
}

static inline int setpgid(pid_t pid, pid_t pgid);
static inline int setpgid(pid_t pid, pid_t pgid)
{
	register pid_t _pid asm("rdi") = pid;
	register pid_t _pgid asm("rsi") = pgid;
	asm("mov {%0, %%eax | eax, %0}" :: "i" (SYS_setpgid),  "r" (_pid), "r" (_pgid) : "eax");
	int ret;
	asm volatile("syscall" : "=a" (ret) :: "rcx", "r11");
	return ret;
}

static inline int setregid(gid_t rgid, gid_t egid);
static inline int setregid(gid_t rgid, gid_t egid)
{
	register gid_t _rgid asm("edi") = rgid;
	register gid_t _egid asm("esi") = egid;
	asm("mov {%0, %%eax | eax, %0}" :: "i" (SYS_setregid),  "r" (_rgid), "r" (_egid) : "eax");
	int ret;
	asm volatile("syscall" : "=a" (ret) :: "rcx", "r11");
	return ret;
}

static inline int setreuid(uid_t ruid, uid_t euid);
static inline int setreuid(uid_t ruid, uid_t euid)
{
	register uid_t _ruid asm("edi") = ruid;
	register uid_t _euid asm("esi") = euid;
	asm("mov {%0, %%eax | eax, %0}" :: "i" (SYS_setreuid),  "r" (_ruid), "r" (_euid) : "eax");
	int ret;
	asm volatile("syscall" : "=a" (ret) :: "rcx", "r11");
	return ret;
}

static inline pid_t setsid(void);
static inline pid_t setsid(void)
{
	asm("mov {%0, %%eax | eax, %0}" :: "i" (SYS_setsid) : "eax");
	pid_t ret;
	asm volatile("syscall" : "=a" (ret) :: "rcx", "r11");
	return ret;
}

static inline int setuid(uid_t uid);
static inline int setuid(uid_t uid)
{
	register uid_t _uid asm("edi") = uid;
	asm("mov {%0, %%eax | eax, %0}" :: "i" (SYS_setuid),  "r" (_uid) : "eax");
	int ret;
	asm volatile("syscall" : "=a" (ret) :: "rcx", "r11");
	return ret;
}

static inline int symlink(const char *old, const char *new);
static inline int symlink(const char *old, const char *new)
{
	register const char *_old asm("rdi") = old;
	register const char *_new asm("rsi") = new;
	asm("mov {%0, %%eax | eax, %0}" :: "i" (SYS_symlink),  "r" (_old), "r" (_new) : "eax");
	int ret;
	asm volatile("syscall" : "=a" (ret) :: "rcx", "r11");
	return ret;
}

static inline int symlinkat(const char * oldname, int newdfd, const char * newname);
static inline int symlinkat(const char * oldname, int newdfd, const char * newname)
{
	register const char *_oldname asm("rdi") = oldname;
	register int _newdfd asm("esi") = newdfd;
	register const char *_newname asm("rdx") = newname;
	asm("mov {%0, %%eax | eax, %0}" :: "i" (SYS_symlinkat),  "r" (_oldname), "r" (_newdfd), "r" (_newname) : "eax");
	int ret;
	asm volatile("syscall" : "=a" (ret) :: "rcx", "r11");
	return ret;
}

static inline void sync(void);
static inline void sync(void)
{
	asm("mov {%0, %%eax | eax, %0}" :: "i" (SYS_sync) : "eax");
	asm volatile("syscall" ::: "rcx", "r11");
}

static inline int truncate(const char *path, long length);
static inline int truncate(const char *path, long length)
{
	register const char *_path asm("rdi") = path;
	register long _length asm("rsi") = length;
	asm("mov {%0, %%eax | eax, %0}" :: "i" (SYS_truncate),  "r" (_path), "r" (_length) : "eax");
	int ret;
	asm volatile("syscall" : "=a" (ret) :: "rcx", "r11");
	return ret;
}

static inline int unlink(const char *pathname);
static inline int unlink(const char *pathname)
{
	register const char *_pathname asm("rdi") = pathname;
	asm("mov {%0, %%eax | eax, %0}" :: "i" (SYS_unlink),  "r" (_pathname) : "eax");
	int ret;
	asm volatile("syscall" : "=a" (ret) :: "rcx", "r11");
	return ret;
}

static inline int unlinkat(int dfd, const char * pathname, int flag);
static inline int unlinkat(int dfd, const char * pathname, int flag)
{
	register int _dfd asm("edi") = dfd;
	register const char *_pathname asm("rsi") = pathname;
	register int _flag asm("edx") = flag;
	asm("mov {%0, %%eax | eax, %0}" :: "i" (SYS_unlinkat),  "r" (_dfd), "r" (_pathname), "r" (_flag) : "eax");
	int ret;
	asm volatile("syscall" : "=a" (ret) :: "rcx", "r11");
	return ret;
}

static inline ssize_t write(unsigned int fd, const char *buf, size_t count);
static inline ssize_t write(unsigned int fd, const char *buf, size_t count)
{
	register unsigned int _fd asm("edi") = fd;
	register const char *_buf asm("rsi") = buf;
	register size_t _count asm("rdx") = count;
	asm("mov {%0, %%eax | eax, %0}" :: "i" (SYS_write),  "r" (_fd), "r" (_buf), "r" (_count) : "eax");
	ssize_t ret;
	asm volatile("syscall" : "=a" (ret) :: "rcx", "r11");
	return ret;
}

