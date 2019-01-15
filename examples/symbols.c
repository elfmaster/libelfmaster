/*
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
	elf_dynsym_iterator_t ds_iter;
	elf_symtab_iterator_t sm_iter;
	struct elf_symbol symbol;

	if (argc < 2) {
		printf("Usage: %s <binary>\n", argv[0]);
		exit(EXIT_SUCCESS);
	}
	if (elf_open_object(argv[1], &obj,
	    ELF_LOAD_F_FORENSICS, &error) == false) {
		fprintf(stderr, "%s\n", elf_error_msg(&error));
		return -1;
	}
        elf_dynsym_iterator_init(&obj, &ds_iter);
        while (elf_dynsym_iterator_next(&ds_iter, &symbol) == ELF_ITER_OK) {
		printf("%s: %#lx-%#lx\n",symbol.name, symbol.value,
		    symbol.value + symbol.size);
	}
	elf_symtab_iterator_init(&obj, &sm_iter);
	while (elf_symtab_iterator_next(&sm_iter, &symbol) == ELF_ITER_OK) {
		printf("%s: %#lx-%#lx\n",symbol.name, symbol.value,
		    symbol.value + symbol.size);
	}
	elf_close_object(&obj);
}
