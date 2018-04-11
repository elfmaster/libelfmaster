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
	elf_section_iterator_t s_iter;
	struct elf_section section;
	struct elf_plt plt;
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

        if (obj.flags & ELF_SHDRS_F)
                printf("*** Section Headers:\n");
        /*
         * The iterator simply won't print anything if there are no sections
         * so we don't have to nest this block of code
         */
        elf_section_iterator_init(&obj, &s_iter);
        while (elf_section_iterator_next(&s_iter, &section) == ELF_ITER_OK) {
                struct elf_section tmp_section;
		printf("%s: %#lx-%#lx\n", section.name, section.address,
		    section.address + section.size);
#if 0
                printf("\nSection %u\n", count++);
                printf("Name: %s\n", section.name ? section.name : "");
                printf("Addr:   %#lx\n", section.address);
                printf("Off:    %#lx\n", section.offset);
                printf("Size:   %#lx\n", section.size);
                printf("Info:   %u\n", section.info);
                printf("Flags:  %C%C%C\n", section.flags & SHF_ALLOC ? 'A' : ' ',
                    section.flags & SHF_EXECINSTR ? 'X' : ' ',
                    section.flags & SHF_WRITE ? 'W' : ' ');
                if (elf_section_by_index(&obj, section.link, &tmp_section) == true) {
                        if (tmp_section.name != NULL)
                                printf("Link:   %s\n", tmp_section.name);
                        else
                                printf("Link:   %u\n", section.link);
                } else {
                        printf("Link:   %u\n", section.link);
                }
                printf("Align:  %lx\n", section.align);
                printf("EntSiz: %lu\n", section.entsize);

#endif
	}
}
