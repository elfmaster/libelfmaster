#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

/* Make sure we have a data segment for testing purposes */
static int test_dummy = 5;

int _start() {
	int argc;
	long *args;
	long *rbp;
	int i;
	int j = 0;

	/* Extract argc from stack */
        asm __volatile__("mov 8(%%rbp), %%rcx " : "=c" (argc));
  
        /* Extract argv from stack */
        asm __volatile__("lea 16(%%rbp), %%rcx " : "=c" (args));
	
	for (i = 0; i < argc; i++) {
		sleep(10);
		printf("%s\n", args[i]);
	}
	exit(0);
}

