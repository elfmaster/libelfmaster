/*
 * Demonstrates how we modify the sh_addr of the .text section
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
	elf_section_iterator_t iter;
	struct elf_section section;

	if (argc < 2) {
		printf("Usage: %s <binary>\n", argv[0]);
		exit(EXIT_SUCCESS);
	}
	if (elf_open_object(argv[1], &obj,
	    ELF_LOAD_F_STRICT|ELF_LOAD_F_MODIFY, &error) == false) {
		fprintf(stderr, "%s\n", elf_error_msg(&error));
		return -1;
	}
	elf_section_iterator_init(&obj, &iter);
	while (elf_section_iterator_next(&iter, &section) == ELF_ITER_OK) {
		struct elf_section s;

		if (strcmp(section.name, ".text") == 0) {
			memcpy(&s, &section, sizeof(s));
			s.address = 0xdeadbeef;
			elf_section_modify(&obj, iter.index - 1, &s, &error);
		}
	}
	/*
	 * Technically you can call this within the elf_section_iterator_next body,
	 * whereas with elf_symtab/dynsym_modify you cannot. But it makes sense to
	 * call it after you have made all of your changes because it is fairly
	 * expensive.
	 */
	elf_section_commit(&obj);
	elf_section_by_name(&obj, ".text", &section);
	printf("text section modified to sh_addr of: %#lx\n", section.address);
	/*
	 * Unlike elf_section/elf_symtab/elf_dynsym modify, with elf_segment
	 * modify we do not need to call a commit function because we don't
	 * keep any internal abstract representations of the segments.
	 * so we can just close the object and be done.
	 */
	elf_close_object(&obj);
}
