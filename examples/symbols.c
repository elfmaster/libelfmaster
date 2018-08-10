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
	elf_dynsym_iterator_t s_iter;
	struct elf_symbol symbol;

	if (argc < 2) {
		printf("Usage: %s <binary>\n", argv[0]);
		exit(EXIT_SUCCESS);
	}
	if (elf_open_object(argv[1], &obj,
	    ELF_LOAD_F_SMART|ELF_LOAD_F_FORENSICS, &error) == false) {
		fprintf(stderr, "%s\n", elf_error_msg(&error));
		return -1;
	}

        if (obj.flags & ELF_SHDRS_F)
                printf("*** Section Headers:\n");
        /*
         * The iterator simply won't print anything if there are no sections
         * so we don't have to nest this block of code
         */
        elf_dynsym_iterator_init(&obj, &s_iter);
        while (elf_dynsym_iterator_next(&s_iter, &symbol) == ELF_ITER_OK) {
		printf("%s: %#lx-%#lx\n",symbol.name, symbol.value,
		    symbol.value + symbol.size);
	}
}
