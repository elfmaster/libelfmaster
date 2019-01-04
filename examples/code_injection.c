#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <elf.h>
#include <sys/types.h>
#include <search.h>
#include <sys/time.h>
#include <elf.h>
#include <link.h>
#include <stdint.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdbool.h>
#include <search.h>
#include <sys/queue.h>
#include <sys/stat.h>
#include <string.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <errno.h>
#include "../include/libelfmaster.h"
#include "../include/internal.h"

/*
 * Opens a given file and checks if it contains an ELF magic. (More checks can be implemented).
 */
int main (int argc, char **argv) 
{
	elfobj_t obj1;
	elfobj_t obj2;
        elfobj_t objdest;
	elf_error_t error;
	uint64_t p_address;
	uint64_t p_offset;
	bool res;

	// http://shell-storm.org/shellcode/files/shellcode-806.php
	uint8_t stub[] = "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48" \
		         "\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05";
	
	if (argc != 3) {
		printf("Usage: %s <host> <output binary>\n", argv[0]);
		exit(EXIT_SUCCESS);
	}
	if (elf_open_object(argv[1], &obj1, ELF_LOAD_F_STRICT, &error) == false) {
		fprintf(stderr, "%s\n", elf_error_msg(&error));
		return -1;
	}
	/* 
	 * In case the binary payload is residing in disk, we can use these functions to load
	 * it, as if it was an ELF file or some binary blob.
	 *
	if (elf_has_header(argv[2], &res, &error) == false) {
		fprintf(stderr, "%s\n", elf_error_msg(&error));
		return -1;
	}
	if (res) {
		if (elf_open_object(argv[2], &obj2, ELF_LOAD_F_STRICT, &error) == false) {
			fprintf(stderr, "%s\n", elf_error_msg(&error));
			return -1;
		}
	} else {
		if (elf_open_stub(argv[2], &obj2, &error) == false) {
			fprintf(stderr, "%s\n", elf_error_msg(&error));
			return -1;
		}
	}
	 * Otherwise stubs can be also operated as byte-arrays.
	 */

	if (elf_init_stub(&obj2, stub, sizeof(stub), &error) == false) {
		fprintf(stderr, "%s\n", elf_error_msg(&error));
		return -1;
	}
	if (elf_create_object(argv[2], &objdest, &obj1, obj1.size + obj2.size,
			       	ELF_LOAD_F_STRICT, &error) == false) {
		fprintf(stderr, "%s\n", elf_error_msg(&error));
		return -1;
	}
	if (elf_inject_code(&objdest, &obj2, &p_offset, ELF_INJECT_F_POSTPEND, &error) == false) {
		fprintf(stderr, "%s\n", elf_error_msg(&error));
		return -1;
	}
	if(internal_offset_to_address(&objdest, p_offset, &p_address, &error) == false) {
		fprintf(stderr, "%s\n", elf_error_msg(&error));
		return -1;
	}
	printf("Payload written at offset: 0x%lx, address: 0x%lx\n", p_offset, p_address);
	
	if (elf_commit_object(&objdest, objdest.size, 0, &error) == false) {
		fprintf(stderr, "%s\n", elf_error_msg(&error));
		return -1;
	}
	return 0;
}
