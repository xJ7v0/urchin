#!/bin/bash
# Name genwrappers.sh
# Description: Generate syscall wrappers for linux
HEADER="$1/include/linux/syscalls.h"
[[ ! -f $HEADER ]] && echo "Not a valid linux source code directory" && exit 1

# Not in `man unistd.h`
# dup3
UNISTD_SYSCALLS_TYPES=(int	"unsigned int"	int	int	int	int )
UNISTD_SYSCALLS=(      access	alarm		chdir	chown	close	dup )

UNISTD_SYSCALLS_TYPES+=(int 	int	int	int		int	int )
UNISTD_SYSCALLS+=(	dup2	dup3	execve	faccessat	fchdir	fchown )

UNISTD_SYSCALLS_TYPES+=(int 		int		int	int	int	)
UNISTD_SYSCALLS+=(	fchownat	fdatasync	fork	fsync	ftruncate )

UNISTD_SYSCALLS_TYPES+=("char*"	gid_t	uid_t	gid_t	int		pid_t)
UNISTD_SYSCALLS+=(	getcwd	getegid	geteuid	getgid	getgroups 	getpgid)

UNISTD_SYSCALLS_TYPES+=(pid_t	uid_t	int	int	int	off_t	int)
UNISTD_SYSCALLS+=(	getsid	getuid	lchown	link	linkat 	lseek	pause)

# syscall pread64 = ssize_t pread
# syscall pwrite64 = ssize_t pwrite
UNISTD_SYSCALLS_TYPES+=(int	ssize_t	ssize_t	ssize_t	ssize_t		ssize_t)
UNISTD_SYSCALLS+=(	pipe	pread	pwrite	read	readlink	readlinkat)

UNISTD_SYSCALLS_TYPES+=(int	int	int	int		int)
UNISTD_SYSCALLS+=(	rmdir	setgid	setpgid	setregid	setreuid)

UNISTD_SYSCALLS_TYPES+=(pid_t	int	int	int		void	int)
UNISTD_SYSCALLS+=(	setsid	setuid	symlink	symlinkat	sync	truncate)

UNISTD_SYSCALLS_TYPES+=(int	int		ssize_t)
UNISTD_SYSCALLS+=(	unlink	unlinkat	write)

usage()
{
	echo "$1: <DIR>
	<DIR>	Path to Linux source"
}

# linux x86_64
# caller saved: RDI, RSI, RDX, RCX, R8, R9, XMM0-XMM7
# kernel parameters: RAX, RDI, RSI, RDX, R8, R9
# kernel call: syscall
linux_x86_64()
{
OLD_IFS="$IFS"
IFS=$'\n'
CALL_STR="asmlinkage long sys_"

SYS_CALL="$(grep \#define /usr/include/asm/unistd_64.h | cut -d _ -f 4- | cut -d " " -f1)"
for ((i = 0; i<"${#UNISTD_SYSCALLS[@]}"; i++)); do
	FUNC_NAME="${UNISTD_SYSCALLS[$i]}"
	FUNC_PARAMS=$(grep -A10 $CALL_STR "$HEADER" | sed -e 's/^[ \t]*//' | sed -e ':a;N;$!ba;s/,\n/, /g' -e 's/__[[:alpha:]]* //g' | grep -Po "(?<=${CALL_STR}${FUNC_NAME})(?=\().*(?=;)")

	if [[ $FUNC_PARAMS ]]; then
		FUNC_CLEAN=$(echo "$FUNC_PARAMS" | sed -e 's/(/ /' -e 's/)//' )
		IFS=","
		c=0
		REG_64=( rdi rsi rdx r8  r9  r10  )
		REG_32=( edi esi edx r8d r9d r10d )
		unset ASM_INPUT_BUF
		echo "static inline ${UNISTD_SYSCALLS_TYPES[$i]} $FUNC_NAME$FUNC_PARAMS;"
		echo "static inline ${UNISTD_SYSCALLS_TYPES[$i]} $FUNC_NAME$FUNC_PARAMS"
		echo "{"

		# loop through functin arguments
		for j in $FUNC_CLEAN; do
			PTR_FIX="${j//\* /\*}"
			TYPE="$(rev <<<$PTR_FIX | cut -d " " -f2- | rev)"
			VAR="$(rev <<<$PTR_FIX | cut -d " " -f1  | rev)"

			case $TYPE in
			*"int"|*"uid_t"|*"gid_t"|*"off_t")
				if [[ "$VAR" == *"*"* ]]; then
					# get *
					PTRS="${VAR//[^*]/}"
					VAR="${VAR//\*/}"
					echo -e "\tregister$TYPE ${PTRS}_$VAR asm(\"${REG_64[$c]}\") = $VAR;"
				else
					echo -e "\tregister$TYPE _$VAR asm(\"${REG_32[$c]}\") = $VAR;"
				fi;;

			*"size_t"|*"long"|*"pid_t")
				echo -e "\tregister$TYPE _$VAR asm(\"${REG_64[$c]}\") = $VAR;";;

			*"void"|"")
				;;
			*)
				if [[ "$VAR" == *"*"* ]]; then
					PTRS="${VAR//[^*]/}"
					VAR="${VAR//\*/}"
					echo -e "\tregister$TYPE ${PTRS}_$VAR asm(\"${REG_64[$c]}\") = $VAR;"
				else
					echo "unknown type $TYPE"
				fi;;
			esac
			[[ ! -z "$TYPE" ]] && ASM_INPUT_BUF+=" \"r\" (_$VAR),"

			c=$[$c+1]

		done

		IFS=$'\n'
		ASM_INPUT_BUF="${ASM_INPUT_BUF/%,/}"
		[[ ! -z "$ASM_INPUT_BUF" ]] &&\
		   echo -e "\tasm(\"mov {%0, %%eax | eax, %0}\" :: \"i\" (SYS_$FUNC_NAME), $ASM_INPUT_BUF : \"eax\");" \
		|| echo -e "\tasm(\"mov {%0, %%eax | eax, %0}\" :: \"i\" (SYS_$FUNC_NAME) : \"eax\");"

		if [[ ${UNISTD_SYSCALLS_TYPES[$i]} != *"void" ]]; then
			echo -e "\t${UNISTD_SYSCALLS_TYPES[$i]} ret;"
			echo -e "\tasm volatile(\"syscall\" : \"=a\" (ret) :: \"rcx\", \"r11\");"
			echo -e "\treturn ret;"
		else
			echo -e "\tasm volatile(\"syscall\" ::: \"rcx\", \"r11\");"

		fi
		echo "}"
		echo
	fi
done
IFS=$OLD_IFS

}


# linux i386 fastcall
# caller saved: ECX, EDX
# kernel paremeters: EAX, EBX, ECX, EDX, ESI, EDI
# kernel call: int 0x80

# linux arm
# aliases: IP (R12), SP (R13), LR (R14), PC (R15)
# caller saved: R0, R1, R2, R3
# caller saved vpu: S0-S15 (D0-D7, Q0-Q3), D16-D31 (Q8-Q15)
# kernel parameters: R7, R0, R1, R2, R3
# kernel call: swi #0

# linux aarch64
# caller saved:
# kernel parameters:
# kernel call:

# linux mips
# caller saved:
# kernel parameters:
# kernel call:

# linux mips64
# caller saved:
# kernel parameters:
# kernel call:

# linux powerpc
# caller saved:
# kernel parameters:
# kernel call:

# linux powerpc64
# caller saved:
# kernel parameters:
# kernel call:

# linux sparc
# caller saved:
# kernel parameters:
# kernel call:

# linux sparc64
# caller saved:
# kernel parameters:
# kernel call:


linux_generic() {

	for i in $(grep SYS src/linux/x86_64/bits/syscall.h | cut -d '_' -f2- | cut -d ' ' -f1); do

		cat > src/linux/generic/syscalls/${i}.s << _EOF
.include "config.h"
.include "sys/syscall.h"

.global ${i}

${i}:
	MOVE	DEST, SYS_${i}
	KERNEL

	RETURN
_EOF

	done

}

#

# linux x86_64
# .set MOVE, mov
# .set DEST, rax
# .set KERNEL, syscall
# .set RETURN, ret

# linux i386
# .set MOVE, mov
# .set DEST, eax
# .set KERNEL, int 0x80
# .set return, ret

linux_x86_64
