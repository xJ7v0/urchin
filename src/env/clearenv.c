#define _GNU_SOURCE
#include <stdlib.h>

static void dummy(char *old, char *new) {}
weak_alias(dummy, __env_rm_add);

extern char **__environ;

int clearenv()
{
	char **e = __environ;
	__environ = 0;
	if (e) while (*e) __env_rm_add(*e++, 0);
	return 0;
}
