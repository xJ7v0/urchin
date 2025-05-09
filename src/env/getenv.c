#include <stdlib.h>
#include <string.h>

extern char **__environ;

char *getenv(const char *name)
{
	size_t l = __strchrnul(name, '=') - name;
	if (l && !name[l] && __environ)
		for (char **e = __environ; *e; e++)
			if (!strncmp(name, *e, l) && l[*e] == '=')
				return *e + l+1;
	return 0;
}
