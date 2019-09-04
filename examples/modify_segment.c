/*
 * Demonstrates how we modify the p_vaddr of the first LOAD segment.
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
	elf_segment_iterator_t iter;
	struct elf_segment segment;

	if (argc < 2) {
		printf("Usage: %s <binary>\n", argv[0]);
		exit(EXIT_SUCCESS);
	}
	if (elf_open_object(argv[1], &obj,
	    ELF_LOAD_F_STRICT|ELF_LOAD_F_MODIFY, &error) == false) {
		fprintf(stderr, "%s\n", elf_error_msg(&error));
		return -1;
	}
	elf_segment_iterator_init(&obj, &iter);
	while (elf_segment_iterator_next(&iter, &segment) == ELF_ITER_OK) {
		if (segment.offset == 0) {
			struct elf_segment s;

			memcpy(&s, &segment, sizeof(segment));
			s.vaddr = 0xdeadbeef;
			elf_segment_modify(&obj, iter.index - 1, &s, &error);
		}
	}
	/*
	 * Unlike elf_section/elf_symtab/elf_dynsym modify, with elf_segment
	 * modify we do not need to call a commit function because we don't
	 * keep any internal abstract representations of the segments.
	 * so we can just close the object and be done.
	 */
	elf_close_object(&obj);
}
