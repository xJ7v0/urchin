#ifndef _SYS_SHM_H
#define _SYS_SHM_H

#ifdef __cplusplus
extern "C" {
#endif

#include <features.h>

#define __NEED_time_t
#define __NEED_size_t
#define __NEED_pid_t

#include <bits/alltypes.h>

#include <sys/ipc.h>

#include <stdint.h>
#include <sys/syscall.h>

#ifdef _GNU_SOURCE
#define __used_ids		used_ids
#define __swap_attempts		swap_attempts
#define __swap_successes	swap_successes
#endif

#include <bits/shm.h>

#define SHM_R		0400
#define SHM_W		0200

#define SHM_RDONLY	010000
#define SHM_RND		020000
#define SHM_REMAP	040000
#define SHM_EXEC	0100000

#define SHM_LOCK	11
#define SHM_UNLOCK	12
#define SHM_STAT	(13 | (IPC_STAT & 0x100))
#define SHM_INFO	14
#define SHM_STAT_ANY	(15 | (IPC_STAT & 0x100))
#define SHM_DEST	01000
#define SHM_LOCKED	02000
#define SHM_HUGETLB	04000
#define SHM_NORESERVE	010000

#define SHM_HUGE_SHIFT	26
#define SHM_HUGE_MASK	0x3f
#define SHM_HUGE_64KB	(16 << 26)
#define SHM_HUGE_512KB	(19 << 26)
#define SHM_HUGE_1MB	(20 << 26)
#define SHM_HUGE_2MB	(21 << 26)
#define SHM_HUGE_8MB	(23 << 26)
#define SHM_HUGE_16MB	(24 << 26)
#define SHM_HUGE_32MB	(25 << 26)
#define SHM_HUGE_256MB	(28 << 26)
#define SHM_HUGE_512MB	(29 << 26)
#define SHM_HUGE_1GB	(30 << 26)
#define SHM_HUGE_2GB	(31 << 26)
#define SHM_HUGE_16GB	(34U << 26)

typedef unsigned long shmatt_t;

void *shmat(int shmid, const void *addr, int shmflag);
void *shmat(int shmid, const void *addr, int shmflag)
{

	register int _shmid __asm__("edi") = shmid;
	register const void *_addr __asm__("rsi") = addr;
	register int _shmflag __asm__("edx") = shmflag;
	__asm__("mov {%0, %%eax | eax, %0}" :: "i" (SYS_shmat),  "r" (_shmid), "r" (_addr), "r" (_shmflag) : "eax");
	void *ret;
	__asm__ volatile("syscall" : "=a" (ret) :: "rcx", "r11");
	return ret;
}

int shmctl(int, int, struct shmid_ds *);

static inline int shmdt(const void *shmaddr);
static inline int shmdt(const void *shmaddr)
{
	register const void *_shmaddr __asm__("edi") = shmaddr;
	__asm__("mov {%0, %%eax | eax, %0}" :: "i" (SYS_shmdt),  "r" (_shmaddr) : "eax");
	int ret;
	__asm__ volatile("syscall" : "=a" (ret) :: "rcx", "r11");
	return ret;
}

static inline int shmget(key_t key, size_t size, int flag);
static inline int shmget(key_t key, size_t size, int flag)
{
	if (size > PTRDIFF_MAX) size = SIZE_MAX;
	register key_t _key __asm__("edi") = key;
	register int _size __asm__("rsi") = size;
	register int _flag __asm__("edx") = flag;
	__asm__("mov {%0, %%eax | eax, %0}" :: "i" (SYS_shmget),  "r" (_key), "r" (_size), "r" (_flag) : "eax");
	int ret;
	__asm__ volatile("syscall" : "=a" (ret) :: "rcx", "r11");
	return ret;
}

#ifdef __cplusplus
}
#endif

#endif
