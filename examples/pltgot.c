/*
 * Prints the dynamic symbol names with the corresponding PLT address
 * Same as plt_dump2, but uses the plt iterator.
 */

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
	elf_pltgot_iterator_t pltgot_iter;
	struct elf_pltgot pltgot;

	if (argc < 2) {
		printf("Usage: %s <binary>\n", argv[0]);
		exit(EXIT_SUCCESS);
	}
	if (elf_open_object(argv[1], &obj, ELF_LOAD_F_FORENSICS, &error) == false) {
		fprintf(stderr, "%s\n", elf_error_msg(&error));
		return -1;
	}
	elf_pltgot_iterator_init(&obj, &pltgot_iter);
	while (elf_pltgot_iterator_next(&pltgot_iter, &pltgot) == ELF_ITER_OK) {
		printf("GOT (%#lx): %#08lx %s\n", pltgot.offset,
		    pltgot.value, elf_pltgot_flag_string(pltgot.flags));
	}
	return 0;
}
