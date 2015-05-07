#include <stdio.h>

typedef struct header {
	struct header * ptr;
	unsigned int size;
} Header;

void * mymalloc(unsigned int);
static Header * morecore(unsigned int);
void myfree(void *);
void myfltraverse();
