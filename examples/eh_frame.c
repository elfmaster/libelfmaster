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
	elf_eh_frame_iterator_t iter;
	struct elf_eh_frame fde;
	size_t count = 0;

	if (argc < 2) {
		printf("Usage: %s <binary>\n", argv[0]);
		exit(EXIT_SUCCESS);
	}
	if (elf_open_object(argv[1], &obj,
	    ELF_LOAD_F_SMART|ELF_LOAD_F_FORENSICS, &error) == false) {
		fprintf(stderr, "%s\n", elf_error_msg(&error));
		return -1;
	}
	printf("Reconstructed function data from PT_GNU_EH_FRAME\n");
        elf_eh_frame_iterator_init(&obj, &iter);
        while (elf_eh_frame_iterator_next(&iter, &fde) == ELF_ITER_OK) {
		printf("Function: %#llx - %#llx\n", fde.pc_begin, fde.pc_end);
	}
	elf_close_object(&obj);
	exit(EXIT_SUCCESS);
}
