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

/* includes
bool elf_create_object(const char *path, struct elfobj *obj, size_t size, uint64_t load_flags, elf_error_t *); 
bool elf_inject_code(struct elfobj_t *host, struct elfobj_t *target, void *payload, uint64_t injection_flags, elf_error_t *error);
bool elf_commit_object(struct elfobj *obj, size_t size, int offset, elf_error_t *error);
*/

// macros
#define ELF_INJECT_DATA 		0
#define ELF_INJECT_REVERSE_CODE		1

// -----------------------------------ulexec
bool
elf_create_object(const char *path, struct elfobj *obj, struct elfobj *copy, size_t size, uint64_t load_flags, elf_error_t *error) 
{
	int fd;
	unsigned int open_flags = O_RDWR|O_CREAT|O_APPEND;
	unsigned int mmap_perms = PROT_READ|PROT_WRITE;
	unsigned int mmap_flags = MAP_PRIVATE;
	uint8_t *mem;

	/*
	 * we count on this being initialized for various sanity checks.
	 */
	memset(obj, 0, sizeof(*obj));	

	/*
	 * we check if the file wants to be created containing a particular elf object
	 */
	if (copy != NULL) {
		memcpy(obj, copy, sizeof(struct elfobj));
		memcpy(obj->mem, copy->mem, copy->size);
	}
	obj->load_flags = load_flags;
	obj->path = path;

	if (load_flags & ELF_LOAD_F_MODIFY) {
		mmap_flags = MAP_SHARED;
	}
	fd = open(path, open_flags, S_IRUSR | S_IRGRP | S_IROTH);
	if (fd < 0) {
		elf_error_set(error, "open: %s", strerror(errno));
		return false;
	}
	obj->fd = fd;

	if (size != 0 && copy == NULL) {
		obj->size = size;
		mem = mmap(NULL, obj->size, mmap_perms, mmap_flags, fd, 0);
		if (mem == MAP_FAILED) {
			elf_error_set(error, "mmap: %s", strerror(errno));
			close(fd);
			return false;
		}
		obj->mem = mem;
	} else if (size == 0 && copy == NULL) {
		fprintf(stderr, "Invalid argument: size\n");
		return false;
	}
	return true;
}

bool 
elf_commit_object(struct elfobj *obj, size_t size, int offset, elf_error_t *error) 
{
	if (pwrite(obj->fd, obj->mem, size, offset) != size) {
		elf_error_set(error, "pwrite: %s", strerror(errno));
		return false;
	}
	return true;
}

bool elf_inject_code(struct elfobj *host, struct elfobj *target, void *payload, uint64_t injection_flags, elf_error_t *error) 
{
	return true;	
}


int main (int argc, char **argv) 
{
	elfobj_t obj1, obj2;
	elf_error_t error;
	struct elf_symbol sym;
	uint64_t qw;
	bool res;

	if (argc < 2) {
		printf("Usage: %s <binary>, <output binary>\n", argv[0]);
		exit(EXIT_SUCCESS);
	}
	if (elf_open_object(argv[1], &obj1, ELF_LOAD_F_STRICT, &error) == false) {
		fprintf(stderr, "%s\n", elf_error_msg(&error));
		return -1;
	}
	printf("File %s was loaded\n", argv[1]);
	
	if (elf_create_object(argv[2], &obj2, &obj1, obj1.size, ELF_LOAD_F_STRICT, &error) == false) {
		fprintf(stderr, "%s\n", elf_error_msg(&error));
		return -1;
	}
	if (elf_commit_object(&obj2, obj2.size, 0, &error) == false) {
		fprintf(stderr, "%s\n", elf_error_msg(&error));
		return -1;
	}
	printf("File %s was created\n", argv[2]);

}
