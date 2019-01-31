# General notes

```
It is often times desirable to modify certain ELF structures, however it breaks the
convention of using the API when directly accessing the ELF structures from the
elfobj_t struct which is meant to be an opaque type. There are now accessor write
functions for modifying symbol table entries, segment entries, and section header
entries. In the future we will add the ability to modify other areas as well such
as notes, dynamic segment, etc.

Do not confuse these accessors with the soon to be merged instrumentation API functions
that @ulexec is adding into the code base, however these accessor write functions are
used by that code on the back-end.

Please see examples/modify_*.c and read the comments as well for caveats. This will show
you how to modify a given structure. Often times structures will be modified by index,
and within the body of an iterator function. Every iterator has an index value; make sure
to use index - 1, when modifying an object. For example:

/*
 * Demonstrates how to modify symbol entries in .symtab
 * where we modify each entries st_value member.
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
	elf_symtab_iterator_t sm_iter;
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
	elf_symtab_iterator_init(&obj, &sm_iter);
	while (elf_symtab_iterator_next(&sm_iter, &symbol) == ELF_ITER_OK) {
		struct elf_symbol sym;

		printf("%s: %#lx-%#lx\n",symbol.name, symbol.value,
		    symbol.value + symbol.size);
		memcpy(&sym, &symbol, sizeof(struct elf_symbol));
		sym.value = 0xdeadbeef;
		if (elf_symtab_modify(&obj, sm_iter.index - 1, &sym, &error) == false) {
			printf("Failed to modify elf symbol table: %s\n", elf_error_msg(&error));
		}
	}
	/*
	 * NOTE: commit cannot be called inside of the symtab iterator,
	 * this will be fixed in the future.
	 */
	elf_symtab_commit(&obj);
	elf_symtab_iterator_init(&obj, &sm_iter);
	printf("After .symtab modification\n");
	 while (elf_symtab_iterator_next(&sm_iter, &symbol) == ELF_ITER_OK) {
		struct elf_symbol sym;

		printf("%s: %#lx-%#lx\n",symbol.name, symbol.value,
		    symbol.value + symbol.size);
	}

	elf_close_object(&obj);
}
