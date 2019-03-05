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
	if (elf_flags(&obj, ELF_SCOP_F) == true) {
		printf("SCOP binary\n");
	}
	ssize_t ret = elf_scop_text_filesz(&obj);
	printf("ret: %zu\n", ret);
	if (ret > 0) {
		printf("Total text segment size: %lu bytes\n", ret);
	}
	printf("Phdr table size: %ld\n", elf_phdr_table_size(&obj));
	printf("elf_executable_text_base: %lx offset: %lx\n", elf_executable_text_base(&obj),
	    elf_executable_text_offset(&obj));
	elf_close_object(&obj);
}
