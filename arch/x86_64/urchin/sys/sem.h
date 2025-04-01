#ifndef _SYS_SEM_H
#define _SYS_SEM_H
#ifdef __cplusplus
extern "C" {
#endif

#include <features.h>

#define __NEED_size_t
#define __NEED_pid_t
#define __NEED_time_t
#ifdef _GNU_SOURCE
#define __NEED_struct_timespec
#endif
#include <bits/alltypes.h>

#include <sys/ipc.h>

#define SEM_UNDO	0x1000
#define GETPID		11
#define GETVAL		12
#define GETALL		13
#define GETNCNT		14
#define GETZCNT		15
#define SETVAL		16
#define SETALL		17

#include <bits/sem.h>

#define _SEM_SEMUN_UNDEFINED 1

#define SEM_STAT (18 | (IPC_STAT & 0x100))
#define SEM_INFO 19
#define SEM_STAT_ANY (20 | (IPC_STAT & 0x100))

struct  seminfo {
	int semmap;
	int semmni;
	int semmns;
	int semmnu;
	int semmsl;
	int semopm;
	int semume;
	int semusz;
	int semvmx;
	int semaem;
};

struct sembuf {
	unsigned short sem_num;
	short sem_op;
	short sem_flg;
};

int semctl(int, int, int, ...);

static inline int semget(key_t key, int nsems, int semflg);
static inline int semget(key_t key, int nsems, int semflg)
{
	/* The kernel uses the wrong type for the sem_nsems member
	 * of struct semid_ds, and thus might not check that the
	 * n fits in the correct (per POSIX) userspace type, so
	 * we have to check here. */
	if (n > USHRT_MAX) return __syscall_ret(-EINVAL);
	register key_t _key __asm__("edi") = key;
	register int _nsems __asm__("rsi") = nsems;
	register int _semflg __asm__("edx") = semflg;
	__asm__("mov {%0, %%eax | eax, %0}" :: "i" (SYS_semget),  "r" (_key), "r" (_nsems), "r" (_semflg) : "eax");
	int ret;
	__asm__ volatile("syscall" : "=a" (ret) :: "rcx", "r11");
	return ret;
}

static inline int semop(int semid, struct sembuf *sops, size_t nsops);
static inline int semop(int semid, struct sembuf *sops, size_t nsops)
{
	register int _semid __asm__("edi") = semid;
	register struct sembuf _sops __asm__("rsi") = sops;
	register size_t _nsops __asm__("edx") = nsops;
	__asm__("mov {%0, %%eax | eax, %0}" :: "i" (SYS_semop),  "r" (_semid), "r" (_sops), "r" (_nsops) : "eax");
	int ret;
	__asm__ volatile("syscall" : "=a" (ret) :: "rcx", "r11");
	return ret;
}


#ifdef _GNU_SOURCE
int semtimedop(int, struct sembuf *, size_t, const struct timespec *);
#endif

#if _REDIR_TIME64
#ifdef _GNU_SOURCE
__REDIR(semtimedop, __semtimedop_time64);
#endif
#endif

#ifdef __cplusplus
}
#endif
#endif
