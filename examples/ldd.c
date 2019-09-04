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
	struct elf_shared_object object;
	struct elf_shared_object_iterator so_iter;

	if (argc < 2) {
		printf("Usage: %s <dynamic binary>\n", argv[0]);
		exit(EXIT_SUCCESS);
	}

	if (elf_open_object(argv[1], &obj, ELF_LOAD_F_FORENSICS, &error) == false) {
		fprintf(stderr, "%s\n", elf_error_msg(&error));
		return -1;
	}

	if (elf_shared_object_iterator_init(&obj, &so_iter,
	    NULL, ELF_SO_RESOLVE_ALL_F, &error) == false) {
		fprintf(stderr, "elf_shared_object_iterator_init failed: %s\n",
		    elf_error_msg(&error));
		return -1;
        }
	for (;;) {
		elf_iterator_res_t res;
		res = elf_shared_object_iterator_next(&so_iter, &object, &error);
		if (res == ELF_ITER_DONE)
			break;
		if (res == ELF_ITER_ERROR) {
			fprintf(stderr, "shared object iterator failed: %s\n",
			    elf_error_msg(&error));
			break;
		}
		if (res == ELF_ITER_OK) {
			printf("%-30s -->\t%s\n", object.basename, object.path);
		} else if (res == ELF_ITER_NOTFOUND) {
			printf("%-30s -->\t%s\n", object.basename, object.path);
		}
	}
	elf_close_object(&obj);
	exit(0);
}
