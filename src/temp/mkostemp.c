#define _BSD_SOURCE
#include <stdlib.h>

hidden int __mkostemps(char *, int, int);

int mkostemp(char *template, int flags)
{
	return __mkostemps(template, 0, flags);
}
