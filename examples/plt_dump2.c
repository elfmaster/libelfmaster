/*
 * Prints the dynamic symbol names with the corresponding PLT address
 * Same as plt_dump, but uses the dynamic symbol iterator
 * and then looks up each symbol name via the PLT cache.
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
	elf_dynsym_iterator_t iter;
	struct elf_symbol symbol;	
	struct elf_plt plt;
	

	if (argc < 2) {
		printf("Usage: %s <binary>\n", argv[0]);
		exit(EXIT_SUCCESS);
	}
	if (elf_open_object(argv[1], &obj, ELF_LOAD_F_FORENSICS, &error) == false) {
		fprintf(stderr, "%s\n", elf_error_msg(&error));
		return -1;
	}
	elf_dynsym_iterator_init(&obj, &iter);
	while (elf_dynsym_iterator_next(&iter, &symbol) == ELF_ITER_OK) {
		if (elf_plt_by_name(&obj, symbol.name, &plt) == true)
			printf("%#08lx %s\n", plt.addr, plt.symname);
	}
	elf_close_object(&obj);
	return 0;
}
