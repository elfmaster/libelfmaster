#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <stdarg.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdint.h>
#include <errno.h>

#include "../include/libelfmaster.h"

bool
elf_error_set(elf_error_t *error, const char *fmt, ...)
{
	va_list va;

	va_start(va, fmt);
	vsnprintf(error->string, sizeof(error->string), fmt, va);
	va_end(va);
	error->_errno = errno;
	return false;
}

const char *
elf_error_msg(elf_error_t *error)
{

	return (const char *)error->string;
}

/*
 * Secure ELF loader.
 */
bool
load_elf_object(const char *path, struct elfobj *obj, bool modify,
    elf_error_t *error)
{
	int fd, i;
	unsigned int open_flags = O_RDONLY;
	unsigned int mmap_perms = PROT_READ;
	unsigned int mmap_flags = MAP_PRIVATE;
	uint8_t *mem;
	uint16_t e_machine;
	struct stat st;

	ElfW(Ehdr) *ehdr;
	ElfW(Phdr) *phdr;
	ElfW(Shdr) *shdr;

	if (modify == true) {
		open_flags = O_RDWR;
		mmap_perms = PROT_READ|PROT_WRITE;
		mmap_flags = MAP_SHARED;
	}

	fd = open(path, open_flags);
	if (fd < 0) {
		elf_error_set(error, "open: %s", strerror(errno));
		return false;
	}

	if (fstat(fd, &st) < 0) {
		elf_error_set(error, "fstat: %s", strerror(errno));
		close(fd);
		return false;
	}

	obj->size = st.st_size;

	mem = mmap(NULL, st.st_size, mmap_perms, mmap_flags, fd, 0);
	if (mem == MAP_FAILED) {
		elf_error_set(error, "mmap: %s", strerror(errno));
		close(fd);
		return false;
	}

	if (memcmp(mem, "\x7f\x45\x4c\x46", 4) != 0) {
		elf_error_set(error, "invalid ELF file magic", strerror(errno));
		goto err;
	}

	obj->type = *(uint16_t *)((uint8_t *)&mem[16]);
	e_machine = *(uint16_t *)((uint8_t *)&mem[18]);

	/*
	 * Set the ELF header pointers as contingent upon the supported arch
	 * types. Also enforce some rudimentary security checks/sanity checks
	 * to prevent possible invalid memory derefs down the road.
	 */
	switch(e_machine) {
	case EM_386:
		obj->arch = i386;
		obj->ehdr32 = (Elf32_Ehdr *)mem;
		obj->phdr32 = (Elf32_Phdr *)&mem[ehdr->e_phoff];
		obj->shdr32 = (Elf32_Shdr *)&mem[ehdr->e_shoff];
		if (obj->ehdr32->e_shstrndx > obj->size) {
			elf_error_set(error, "invalid e_shstrndx: %u\n",
			    obj->ehdr32->e_shstrndx);
			goto err;
		}
		obj->shstrtab =
		    (char *)&mem[shdr[obj->ehdr32->e_shstrndx].sh_offset];
		if ((obj->ehdr32->e_phoff +
		    (obj->ehdr32->e_phnum * sizeof(Elf32_Phdr))) > obj->size) {
			elf_error_set(error, "unsafe phdr values");
			goto err;
		}
		if ((obj->ehdr32->e_shoff +
		    (obj->ehdr32->e_shnum * sizeof(Elf32_Shdr))) > obj->size) {
			elf_error_set(error, "unsafe shdr value");
			goto err;
		}
		if (obj->ehdr32->e_phentsize != sizeof(Elf32_Phdr)) {
			elf_error_set(error, "invalid e_phentsize: %u\n",
			    obj->ehdr32->e_phentsize);
			goto err;
		}
		if (obj->ehdr32->e_shentsize != sizeof(Elf32_Shdr)) {
			elf_error_set(error, "invalid e_shentsize: %u\n",
			    obj->ehdr32->e_shentsize);
			goto err;
		}
		break;
	case EM_X86_64:
		obj->arch = x64;
		obj->ehdr64 = (Elf64_Ehdr *)mem;
		obj->phdr64 = (Elf64_Phdr *)&mem[ehdr->e_phoff];
		obj->shdr64 = (Elf64_Shdr *)&mem[ehdr->e_shoff];
		if (obj->ehdr64->e_shstrndx > obj->size) {
			elf_error_set(error, "invalid e_shstrndx: %lu\n",
			    obj->ehdr64->e_shstrndx);
			goto err;
		}
		obj->shstrtab =
		    (char *)&mem[shdr[obj->ehdr64->e_shstrndx].sh_offset];
		if ((obj->ehdr64->e_phoff +
		    (obj->ehdr64->e_phnum * sizeof(Elf64_Phdr))) > obj->size) {
			elf_error_set(error, "unsafe phdr values");
			goto err;
		}
		if ((obj->ehdr64->e_shoff +
		    (obj->ehdr64->e_shnum * sizeof(Elf64_Shdr))) > obj->size) {
			elf_error_set(error, "unsafe shdr values");
			goto err;
		}
		if (obj->ehdr64->e_phentsize != sizeof(Elf64_Phdr)) {
			elf_error_set(error, "invalid e_phentsize: %u\n",
			    obj->ehdr64->e_phentsize);
			goto err;
		}
		if (obj->ehdr64->e_shentsize != sizeof(Elf64_Shdr)) {
			elf_error_set(error, "invalid_e_shentsize: %u\n",
			    obj->ehdr64->e_shentsize);
			goto err;
		}
		break;
	default:
		elf_error_set(error, "unsupported ELF architecture", strerror(errno));
		goto err;
	}

	for (i = 0; i < ehdr->e_shnum; i++) {
		if (strcmp(&obj->shstrtab[shdr[i].sh_name], ".strtab") == 0) {
			obj->strtab = (char *)&mem[shdr[i].sh_offset];
		} else if (strcmp(&obj->shstrtab[shdr[i].sh_name],
		    ".symtab") == 0) {
			switch(obj->arch) {
			case i386:
				obj->symtab32 =
				    (Elf32_Sym *)&mem[shdr[i].sh_offset];
				break;
			case x64:
				obj->symtab64 =
				    (Elf64_Sym *)&mem[shdr[i].sh_offset];
				break;
			}
		} else if (strcmp(&obj->shstrtab[shdr[i].sh_name],
		    ".dynsym") == 0) {
			switch(obj->arch) {
			case i386:
				obj->dynsym32 =
				    (Elf32_Sym *)&mem[shdr[i].sh_offset];
				break;
			case x64:
				obj->dynsym64 =
				    (Elf64_Sym *)&mem[shdr[i].sh_offset];
				break;
			}
		} else if (strcmp(&obj->shstrtab[shdr[i].sh_name],
		    ".dynstr") == 0) {
			obj->dynstr = (char *)&mem[shdr[i].sh_offset];
		} else if (strcmp(&obj->shstrtab[shdr[i].sh_name],
		    ".strtab") == 0) {
			obj->strtab = (char *)&mem[shdr[i].sh_offset];
		}
	}
	return true;
err:
	close(fd);
	munmap(mem, st.st_size);
	return false;
}

