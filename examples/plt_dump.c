#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <elf.h>
#include <sys/types.h>
#include <search.h>
#include <sys/time.h>
#include "../include/libelfmaster.h"

int main(int argc, char **argv)
{
	elfobj_t obj;
	elf_error_t error;
	elf_plt_iterator_t iter;
	struct elf_plt plt;

	if (argc < 2) {
		printf("Usage: %s <binary>\n", argv[0]);
		exit(EXIT_SUCCESS);
	}
	if (elf_open_object(argv[1], &obj, false, &error) == false) {
		fprintf(stderr, "%s\n", elf_error_msg(&error));
		return -1;
	}
	elf_plt_iterator_init(&obj, &iter);
	for (;;) {
		switch(elf_plt_iterator_next(&iter, &plt)) {
		case ELF_ITER_DONE:
			goto out;
		case ELF_ITER_ERROR:
			fprintf(stderr, "elf_plt_iterator_next failed\n");
			goto out;
		case ELF_ITER_OK:
			printf("%#08lx: %s\n", plt.addr, plt.symname);
			break;
		}
	}
out:
	return 0;
}
