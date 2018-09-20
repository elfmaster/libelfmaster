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
	struct elf_symbol sym;	
	uint64_t qw;
	bool res;

	if (argc < 2) {
		printf("Usage: %s <binary>\n", argv[0]);
		exit(EXIT_SUCCESS);
	}
	if (elf_open_object(argv[1], &obj, ELF_LOAD_F_FORENSICS, &error) == false) {
		fprintf(stderr, "%s\n", elf_error_msg(&error));
		return -1;
	}

	elf_symbol_by_name(&obj, "main", &sym);
	res = elf_read_address(&obj, sym.value, &qw, ELF_QWORD);
	if (res == true)
		printf("read value: %lx\n", qw);
	return 0;
}
