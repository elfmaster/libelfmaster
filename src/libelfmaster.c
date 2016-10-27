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
 * TODO, switch to using qsort_r, and add two separate sorted arrays
 * of pointers to section structs. One which is sorted by address, and
 * one sorted by name.
 */
static int
section_name_cmp(const void *p0, const void *p1)
{
	const char *s1 = (*(struct elf_section **)p0)->name;
	const char *s2 = (*(struct elf_section **)p1)->name;

	return strcmp(s1, s2);
}

bool
get_elf_section_by_name(struct elfobj *obj, const char *name,
    struct elf_section *out)
{
	struct elf_section key, *res;

	key.name = (char *)name;
	res = bsearch(&key, obj->sections, obj->section_count,
	    sizeof(struct elf_section), section_name_cmp);
	if (res == NULL)
		return false;
	memcpy(out, res, sizeof(*out));
	return true;
}

void
elf_section_iterator_init(struct elfobj *obj, struct elf_section_iterator *iter)
{

	iter->index = 0;
	iter->obj = obj;
	return;
}

/*
 * We don't use obj->sections, since that is sorted. Instead we re-create an 'struct
 * elf_section' for each entry, and print them in the order the actual section headers
 * are listed in the binary.
 */
elf_iterator_res_t
elf_section_iterator_next(struct elf_section_iterator *iter, struct elf_section *section)
{
	elfobj_t *obj = iter->obj;

	if (iter->index >= obj->section_count)
		return ELF_ITER_DONE;

	switch(obj->arch) {
	case i386:
		section->name = &obj->shstrtab[obj->shdr32[iter->index].sh_offset];
		section->type = obj->shdr32[iter->index].sh_type;
		section->link = obj->shdr32[iter->index].sh_link;
		section->info = obj->shdr32[iter->index].sh_info;
		section->flags = obj->shdr32[iter->index].sh_flags;
		section->align = obj->shdr32[iter->index].sh_addralign;
		section->entsize = obj->shdr32[iter->index].sh_entsize;
		section->offset = obj->shdr32[iter->index].sh_offset;
		section->address = obj->shdr32[iter->index].sh_addr;
		section->size = obj->shdr32[iter->index].sh_size;
		break;
	case x64:
		section->name = &obj->shstrtab[obj->shdr64[iter->index].sh_offset];
		section->type = obj->shdr64[iter->index].sh_type;
		section->link = obj->shdr64[iter->index].sh_link;
		section->info = obj->shdr64[iter->index].sh_info;
		section->flags = obj->shdr64[iter->index].sh_flags;
		section->align = obj->shdr64[iter->index].sh_addralign;
		section->entsize = obj->shdr64[iter->index].sh_entsize;
		section->offset = obj->shdr64[iter->index].sh_offset;
		section->address = obj->shdr64[iter->index].sh_addr;
		section->size = obj->shdr64[iter->index].sh_offset;
		break;
	default:
		return ELF_ITER_ERROR;
	}
	return ELF_ITER_OK;
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
	size_t shstrtab_size, section_count;

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
		obj->phdr32 = (Elf32_Phdr *)&mem[obj->ehdr32->e_phoff];
		obj->shdr32 = (Elf32_Shdr *)&mem[obj->ehdr32->e_shoff];
		obj->segment_count = obj->ehdr32->e_phnum;
		if (obj->ehdr32->e_shstrndx > obj->size) {
			elf_error_set(error, "invalid e_shstrndx: %u\n",
			    obj->ehdr32->e_shstrndx);
			goto err;
		}
		obj->shstrtab =
		    (char *)&mem[obj->shdr32[obj->ehdr32->e_shstrndx].sh_offset];
		shstrtab_size = obj->shdr32[obj->ehdr32->e_shstrndx].sh_size;
		obj->section_count = section_count = obj->ehdr32->e_shnum;
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
			elf_error_set(error, "invalid e_phentsize: %u",
			    obj->ehdr32->e_phentsize);
			goto err;
		}
		if (obj->ehdr32->e_shentsize != sizeof(Elf32_Shdr)) {
			elf_error_set(error, "invalid e_shentsize: %u",
			    obj->ehdr32->e_shentsize);
			goto err;
		}
		break;
	case EM_X86_64:
		obj->arch = x64;
		obj->ehdr64 = (Elf64_Ehdr *)mem;
		obj->phdr64 = (Elf64_Phdr *)&mem[obj->ehdr64->e_phoff];
		obj->shdr64 = (Elf64_Shdr *)&mem[obj->ehdr64->e_shoff];
		obj->segment_count = obj->ehdr64->e_phnum;
		if (obj->ehdr64->e_shstrndx > obj->size) {
			elf_error_set(error, "invalid e_shstrndx: %lu",
			    obj->ehdr64->e_shstrndx);
			goto err;
		}
		obj->shstrtab =
		    (char *)&mem[obj->shdr64[obj->ehdr64->e_shstrndx].sh_offset];
		shstrtab_size = obj->shdr64[obj->ehdr64->e_shstrndx].sh_size;
		obj->section_count = section_count = obj->ehdr64->e_shnum;
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
			elf_error_set(error, "invalid e_phentsize: %u",
			    obj->ehdr64->e_phentsize);
			goto err;
		}
		if (obj->ehdr64->e_shentsize != sizeof(Elf64_Shdr)) {
			elf_error_set(error, "invalid_e_shentsize: %u",
			    obj->ehdr64->e_shentsize);
			goto err;
		}
		break;
	default:
		elf_error_set(error, "unsupported ELF architecture",
		    strerror(errno));
		goto err;
	}

	/*
	 * Lets sort the section header string table.
	 */
	obj->sections = (struct elf_section **)
	    malloc(sizeof(struct elf_section *) * section_count);
	if (obj->sections == NULL) {
		elf_error_set(error, "malloc: %s", strerror(errno));
		goto err;
	}
	for (i = 0; i < section_count; i++) {
		switch(obj->arch) {
		case i386:
			obj->sections[i]->name =
			    strdup(&obj->shstrtab[obj->shdr32[obj->shdr32[i].sh_name].sh_offset]);
			obj->sections[i]->type = obj->shdr32[i].sh_type;
			obj->sections[i]->link = obj->shdr32[i].sh_link;
			obj->sections[i]->info = obj->shdr32[i].sh_info;
			obj->sections[i]->flags = obj->shdr32[i].sh_flags;
			obj->sections[i]->align = obj->shdr32[i].sh_addralign;
			obj->sections[i]->entsize = obj->shdr32[i].sh_entsize;
			obj->sections[i]->offset = obj->shdr32[i].sh_offset;
			obj->sections[i]->address = obj->shdr32[i].sh_addr;
			obj->sections[i]->size = obj->shdr32[i].sh_size;
			break;
		case x64:
			obj->sections[i]->name =
			    strdup(&obj->shstrtab[obj->shdr64[obj->shdr64[i].sh_name].sh_offset]);
			obj->sections[i]->type = obj->shdr64[i].sh_type;
			obj->sections[i]->link = obj->shdr64[i].sh_link;
			obj->sections[i]->info = obj->shdr64[i].sh_info;
			obj->sections[i]->flags = obj->shdr64[i].sh_flags;
			obj->sections[i]->align = obj->shdr64[i].sh_addralign;
			obj->sections[i]->entsize = obj->shdr64[i].sh_entsize;
			obj->sections[i]->offset = obj->shdr64[i].sh_offset;
			obj->sections[i]->address = obj->shdr64[i].sh_addr;
			obj->sections[i]->size = obj->shdr64[i].sh_size;
			break;
		}
	}

	qsort(obj->sections, section_count,
	    sizeof(struct elf_section), section_name_cmp);

	/*
	 * Set the remaining elf object pointers to the various data structures in the
	 * ELF file.
	 */
	for (i = 0; i < section_count; i++) {
		const char *sname = (obj->arch == i386) ?
		    &obj->shstrtab[obj->shdr32[i].sh_name] :
		    &obj->shstrtab[obj->shdr64[i].sh_name];
		uint64_t sh_offset = (obj->arch == i386) ?
		    obj->shdr32[i].sh_offset : obj->shdr64[i].sh_offset;

		if (strcmp(sname, ".strtab") == 0) {
			obj->strtab = (char *)&mem[sh_offset];
		/*
		 * Setup the symbol table, dynamic symbol table,
		 * and string table pointers.
		 */
		} else if (strcmp(sname, ".symtab") == 0) {
			switch(obj->arch) {
			case i386:
				obj->symtab32 =
				    (Elf32_Sym *)&mem[sh_offset];
				break;
			case x64:
				obj->symtab64 =
				    (Elf64_Sym *)&mem[sh_offset];
				break;
			}
		} else if (strcmp(sname, ".dynsym") == 0) {
			switch(obj->arch) {
			case i386:
				obj->dynsym32 =
				    (Elf32_Sym *)&mem[sh_offset];
				break;
			case x64:
				obj->dynsym64 =
				    (Elf64_Sym *)&mem[sh_offset];
				break;
			}
		} else if (strcmp(sname, ".dynstr") == 0) {
			obj->dynstr = (char *)&mem[sh_offset];
		} else if (strcmp(sname, ".strtab") == 0) {
			obj->strtab = (char *)&mem[sh_offset];
		}
	}
	return true;
err:
	close(fd);
	munmap(mem, st.st_size);
	return false;
}


