/*
 * Demonstrates how to modify every dynamic symbol table
 * entry, where we modify the st_value's.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <elf.h>
#include <sys/types.h>
#include <search.h>
#include <sys/time.h>
#include <string.h>
#include "../include/libelfmaster.h"

int main(int argc, char **argv)
{
	elfobj_t obj;
	elf_error_t error;
	elf_dynsym_iterator_t ds_iter;
	struct elf_symbol symbol;

	if (argc < 2) {
		printf("Usage: %s <binary>\n", argv[0]);
		exit(EXIT_SUCCESS);
	}
	if (elf_open_object(argv[1], &obj,
	    ELF_LOAD_F_STRICT|ELF_LOAD_F_MODIFY, &error) == false) {
		fprintf(stderr, "%s\n", elf_error_msg(&error));
		return -1;
	}
	elf_dynsym_iterator_init(&obj, &ds_iter);
	while (elf_dynsym_iterator_next(&ds_iter, &symbol) == ELF_ITER_OK) {
		struct elf_symbol sym;

		printf("%s: %#lx-%#lx\n",symbol.name, symbol.value,
		    symbol.value + symbol.size);
		memcpy(&sym, &symbol, sizeof(struct elf_symbol));
		sym.value = 0xdeadbeef;
		/*
		 * NOTE use iter.index - 1, otherwise it will not hit sym[0] and will
		 * eventually go out of bounds.
		 */
		if (elf_dynsym_modify(&obj, ds_iter.index - 1, &sym, &error) == false) {
			printf("Failed to modify elf symbol table: %s\n", elf_error_msg(&error));
		}
	}
	/*
	 * commit cannot be called inside of the dynsym iterator
	 */
	elf_dynsym_commit(&obj);
	elf_dynsym_iterator_init(&obj, &ds_iter);
	printf("After .dynsym modification\n");
	 while (elf_dynsym_iterator_next(&ds_iter, &symbol) == ELF_ITER_OK) {
		struct elf_symbol sym;

		printf("%s: %#lx-%#lx\n",symbol.name, symbol.value,
		    symbol.value + symbol.size);
	}

	elf_close_object(&obj);
}
