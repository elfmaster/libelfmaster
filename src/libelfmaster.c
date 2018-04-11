#include <ctype.h>
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
#include <search.h>

#include "libelfmaster.h"
#include "misc.h"
#include "internal.h"

#define ROUNDUP(x, y) ((x + (y - 1)) & ~(y - 1))

/*
 **** libelfmaster supports ld.so.cache for shared library resolution
*/

#define CACHE_FILE "/etc/ld.so.cache"

#define CACHEMAGIC_VERSION_NEW CACHEMAGIC_NEW CACHE_VERSION

#define ALIGN_CACHE(addr)				\
	(((addr) + __alignof__ (struct cache_file_new) -1)	\
	    & (~(__alignof__ (struct cache_file_new) - 1)))

const char *
elf_error_msg(elf_error_t *error)
{

	return (const char *)error->string;
}

const char *
elf_segment_type_string(uint32_t type)
{

	switch(type) {
	case PT_LOAD:
		return "LOAD";
	case PT_INTERP:
		return "INTERP";
	case PT_TLS:
		return "TLS";
	case PT_GNU_EH_FRAME:
		return "EH_FRAME";
	case PT_PHDR:
		return "PHDR";
	case PT_NOTE:
		return "NOTE";
	case PT_GNU_STACK:
		return "STACK";
	case PT_GNU_RELRO:
		return "RELRO";
	case PT_DYNAMIC:
		return "DYNAMIC";
	case PT_SHLIB:
		return "SHLIB";
	case PT_LOSUNW:
		return "LOSUNW";
	case PT_HIOS:
		return "HIOS";
	case PT_LOPROC:
		return "LOPROC";
	case PT_HIPROC:
		return "HIPROC";
	case PT_PAX_FLAGS:
		return "PAX_FLAGS";
	default:
		return "UNKNOWN";
	}
	return "UNKNOWN";
}

const char *
elf_reloc_type_string(struct elfobj *obj, uint32_t r_type)
{

	/*
	 * For now we only support printing relocations for x86 arch
	 */
	if (elf_machine(obj) != EM_386 && elf_machine(obj) != EM_X86_64)
		return "R_UNKNOWN";

	switch(obj->e_class) {
	case elfclass32:
		switch(r_type) {
		case R_386_NONE:
			return "R_386_NONE";
		case R_386_32:
			return "R_386_32";
		case R_386_PC32:
			return "R_386_PC32";
		case R_386_GOT32:
			return "R_386_GOT32";
		case R_386_PLT32:
			return "R_386_PLT32";
		case R_386_COPY:
			return "R_386_COPY";
		case R_386_GLOB_DAT:
			return "R_386_GLOB_DAT";
		case R_386_JMP_SLOT:
			return "R_386_JUMP_SLOT";
		case R_386_RELATIVE:
			return "R_386_RELATIVE";
		case R_386_GOTOFF:
			return "R_386_GOTOFF";
		case R_386_GOTPC:
			return "R_386_GOTPC";
		case R_386_32PLT:
			return "R_386_32PLT";
		case R_386_TLS_TPOFF:
			return "R_386_TLS_TPOFF";
		case R_386_TLS_LE:
			return "R_386_TLS_LE";
		case R_386_TLS_GD:
			return "R_386_TLS_GD";
		case R_386_TLS_LDM:
			return "R_386_TLS_LDM";
		case R_386_16:
			return "R_386_16";
		case R_386_PC16:
			return "R_386_PC16";
		case R_386_8:
			return "R_386_8";
		case R_386_PC8:
			return "R_386_PC8";
		case R_386_TLS_GD_32:
			return "R_386_TLS_GD_32";
		case R_386_TLS_GD_PUSH:
			return "R_386_TLS_GD_PUSH";
		case R_386_TLS_GD_CALL:
			return "R_386_TLS_GD_CALL";
		case R_386_TLS_GD_POP:
			return "R_386_TLS_GD_POP";
		case R_386_TLS_LDM_32:
			return "R_386_TLS_LDM_32";
		case R_386_TLS_LDM_PUSH:
			return "R_386_TLS_LDM_PUSH";
		case R_386_TLS_LDM_CALL:
			return "R_386_TLS_LDM_CALL";
		case R_386_TLS_LDM_POP:
			return "R_386_TLS_LDM_POP";
		case R_386_TLS_LDO_32:
			return "R_386_TLS_LDO_32";
		case R_386_TLS_IE_32:
			return "R_386_TLS_IE_32";
		case R_386_TLS_LE_32:
			return "R_386_TLS_LE_32";
		case R_386_TLS_DTPMOD32:
			return "R_386_TLS_DTMOD32";
		case R_386_TLS_DTPOFF32:
			return "R_386_TLS_DTOFF32";
		case R_386_TLS_TPOFF32:
			return "R_386_TLS_TPOFF32";
		case R_386_SIZE32:
			return "R_386_TLS_SIZE32";
		case R_386_TLS_GOTDESC:
			return "R_386_TLS_GOTDESC";
		case R_386_TLS_DESC_CALL:
			return "R_386_TLS_DESC_CALL";
		case R_386_TLS_DESC:
			return "R_386_TLS_DESC";
		case R_386_IRELATIVE:
			return "R_386_IRELATIVE";
		default:
			return "UNKNOWN";
		}
	case elfclass64:
		switch(r_type) {
		case R_X86_64_NONE:
			return "R_X86_64_NONE";
		case R_X86_64_64:
			return "R_X86_64_64";
		case R_X86_64_PC32:
			return "R_X86_64_PC32";
		case R_X86_64_GOT32:
			return "R_X86_64_GOT32";
		case R_X86_64_PLT32:
			return "R_X86_64_PLT32";
		case R_X86_64_COPY:
			return "R_X86_64_COPY";
		case R_X86_64_GLOB_DAT:
			return "R_X86_64_GLOB_DAT";
		case R_X86_64_JUMP_SLOT:
			return "R_X86_64_JUMP_SLOT";
		case R_X86_64_RELATIVE:
			return "R_X86_64_RELATIVE";
		case R_X86_64_GOTPCREL:
			return "R_X86_64_GOTPCREL";
		case R_X86_64_32:
			return "R_X86_64_32";
		case R_X86_64_32S:
			return "R_X86_64_32S";
		case R_X86_64_16:
			return "R_X86_64_16";
		case R_X86_64_PC16:
			return "R_X86_64_PC16";
		case R_X86_64_8:
			return "R_X86_64_8";
		case R_X86_64_PC8:
			return "R_X86_64_PC8";
		case R_X86_64_DTPMOD64:
			return "R_X86_64_DTPMOD64";
		case R_X86_64_DTPOFF64:
			return "R_X86_64_DTPOFF64";
		case R_X86_64_TPOFF64:
			return "R_X86_64_TPOFF64";
		case R_X86_64_TLSGD:
			return "R_X86_64_TLSGD";
		case R_X86_64_TLSLD:
			return "R_X86_64_TLSLD";
		case R_X86_64_DTPOFF32:
			return "R_X86_64_DTPOFF32";
		case R_X86_64_GOTTPOFF:
			return "R_X86_64_GOTTPOFF";
		case R_X86_64_TPOFF32:
			return "R_X86_64_TPOFF32";
		case R_X86_64_PC64:
			return "R_X86_64_PC64";
		case R_X86_64_GOTOFF64:
			return "R_X86_64_GOTOFF64";
		case R_X86_64_GOTPC32:
			return "R_X86_64_GOTPC32";
		case R_X86_64_GOT64:
			return "R_X86_64_GOT64";
		case R_X86_64_GOTPCREL64:
			return "R_X86_64_GOTPCREL64";
		case R_X86_64_GOTPC64:
			return "R_X86_64_GOTPC64";
		case R_X86_64_GOTPLT64:
			return "R_X86_64_GOTPLT64";
		case R_X86_64_PLTOFF64:
			return "R_X86_64_PLTOFF64";
		case R_X86_64_SIZE32:
			return "R_X86_64_SIZE32";
		case R_X86_64_SIZE64:
			return "R_X86_64_SIZE64";
		case R_X86_64_GOTPC32_TLSDESC:
			return "R_X86_64_GOTPC32_TLSDESC";
		case R_X86_64_TLSDESC_CALL:
			return "R_X86_64_TLSDESC_CALL";
		case R_X86_64_TLSDESC:
			return "R_X86_64_TLSDESC";
		case R_X86_64_IRELATIVE:
			return "R_X86_64_IRELATIVE";
		case R_X86_64_RELATIVE64:
			return "R_X86_64_RELATIVE64";
		default:
			return "R_UNKNOWN";
		}
	}
	return "R_UNKNOWN";
}

uint64_t
elf_text_base(struct elfobj *obj)
{
	size_t i;

	for (i = 0; i < obj->load_count; i++) {
		if (obj->pt_load[i].flag & ELF_PT_LOAD_TEXT_F) {
			switch(obj->e_class) {
			case elfclass32:
				return obj->pt_load[i].phdr32.p_vaddr;
			case elfclass64:
				return obj->pt_load[i].phdr64.p_vaddr;
			}
		}
	}
	return 0;
}

uint64_t
elf_text_offset(struct elfobj *obj)
{
	size_t i;

	for (i = 0; i < obj->load_count; i++) {
		if (obj->pt_load[i].flag & ELF_PT_LOAD_TEXT_F) {
			switch(obj->e_class) {
			case elfclass32:
				return obj->pt_load[i].phdr32.p_offset;
			case elfclass64:
				return obj->pt_load[i].phdr64.p_offset;
			}
		}
	}
	return 0;
}

uint64_t
elf_data_base(struct elfobj *obj)
{
	size_t i;

	for (i = 0; i < obj->load_count; i++) {
		if (obj->pt_load[i].flag & ELF_PT_LOAD_DATA_F) {
			switch(obj->e_class) {
			case elfclass32:
				return obj->pt_load[i].phdr32.p_vaddr;
			case elfclass64:
				return obj->pt_load[i].phdr64.p_vaddr;
			}
		}
	}
	return 0;
}

uint64_t
elf_data_offset(struct elfobj *obj)
{
	size_t i;

	for (i = 0; i < obj->load_count; i++) {
		if (obj->pt_load[i].flag & ELF_PT_LOAD_DATA_F) {
			switch(obj->e_class) {
			case elfclass32:
				return obj->pt_load[i].phdr32.p_offset;
			case elfclass64:
				return obj->pt_load[i].phdr64.p_offset;
			}
		}
	}
	return 0;
}

void *
elf_address_pointer(struct elfobj *obj, uint64_t address)
{
	uint64_t offset = elf_data_offset(obj) + address - elf_data_base(obj);

	if (offset > obj->size - 1)
		return NULL;
	return (void *)((uint8_t *)&obj->mem[offset]);
}

const char *
elf_section_string(struct elfobj *obj, uint64_t offset)
{

	if (offset >= obj->size)
		return NULL;
	return &obj->shstrtab[offset];
}

const char *
elf_dynamic_string(struct elfobj *obj, uint64_t offset)
{

	if (offset >= obj->size)
		return NULL;
	return &obj->dynstr[offset];
}

const char *
elf_symtab_string(struct elfobj *obj, uint64_t offset)
{

	if (offset >= obj->size)
		return NULL;
	return &obj->strtab[offset];
}

bool
elf_section_by_name(struct elfobj *obj, const char *name,
    struct elf_section *out)
{
	struct elf_section tmp = { .name = (char *)name };
	struct elf_section *key = &tmp;
	struct elf_section **res;

	res = bsearch(&key, obj->sections, obj->section_count,
	   sizeof(struct elf_section *), section_name_cmp);
	if (res == NULL)
		return false;
	memcpy(out, *res, sizeof(*out));
	return true;
}

bool
elf_section_by_index(struct elfobj *obj, uint32_t index,
    struct elf_section *out)
{

        switch(obj->e_class) {
        case elfclass32:
		if (index >= obj->ehdr32->e_shnum)
			return false;
		out->name = &obj->shstrtab[obj->shdr32[index].sh_name];
		out->link = obj->shdr32[index].sh_link;
		out->info = obj->shdr32[index].sh_info;
		out->flags = obj->shdr32[index].sh_flags;
		out->align = obj->shdr32[index].sh_addralign;
		out->entsize = obj->shdr32[index].sh_entsize;
		out->offset = obj->shdr32[index].sh_offset;
		out->address = obj->shdr32[index].sh_addr;
		break;
        case elfclass64:
		if (index >= obj->ehdr64->e_shnum)
			return false;
		out->name = &obj->shstrtab[obj->shdr64[index].sh_name];
		out->link = obj->shdr64[index].sh_link;
		out->info = obj->shdr64[index].sh_info;
		out->flags = obj->shdr64[index].sh_flags;
		out->align = obj->shdr64[index].sh_addralign;
		out->entsize = obj->shdr64[index].sh_entsize;
		out->offset = obj->shdr64[index].sh_offset;
		out->address = obj->shdr64[index].sh_addr;
		break;
	default:
		return false;
        }
	return true;
}

const char *
elf_section_name_by_index(struct elfobj *obj, uint32_t index)
{
	struct elf_section section;

	if (elf_section_by_index(obj, index, &section) == false)
		return NULL;
	return section.name;
}

bool
elf_symbol_by_index(struct elfobj *obj, unsigned int index,
    struct elf_symbol *out, const int which)
{
	union {
		Elf32_Sym *symtab32;
		Elf64_Sym *symtab64;
	} e;

	if (which == SHT_SYMTAB) {
		if (index >= obj->symtab_count)
			return false;
	} else if (which == SHT_DYNSYM) {
		if (index >= obj->dynsym_count)
			return false;
	} else {
		return false;
	}
	switch(obj->e_class) {
	case elfclass32:
		e.symtab32 = which == SHT_SYMTAB ? &obj->symtab32[index] :
		    &obj->dynsym32[index];
		out->name = which == SHT_SYMTAB ? &obj->strtab[e.symtab32->st_name] :
		    &obj->dynstr[e.symtab32->st_name];
		out->value = e.symtab32->st_value;
		out->size = e.symtab32->st_size;
		out->shndx = e.symtab32->st_shndx;
		out->bind = ELF32_ST_BIND(e.symtab32->st_info);
		out->type = ELF32_ST_TYPE(e.symtab32->st_info);
		out->visibility = ELF32_ST_VISIBILITY(e.symtab32->st_other);
		break;
	case elfclass64:
		e.symtab64 = which == SHT_SYMTAB ? &obj->symtab64[index] :
		    &obj->dynsym64[index];
		out->name = which == SHT_SYMTAB ? &obj->strtab[e.symtab64->st_name] :
		    &obj->dynstr[e.symtab64->st_name];
		out->value = e.symtab64->st_value;
		out->size = e.symtab64->st_size;
		out->shndx = e.symtab64->st_shndx;
		out->bind = ELF64_ST_BIND(e.symtab64->st_info);
		out->type = ELF64_ST_TYPE(e.symtab64->st_info);
		out->visibility = ELF64_ST_VISIBILITY(e.symtab64->st_other);
		break;
	default:
		return false;
	}
	return true;
}

bool
elf_symbol_by_name(struct elfobj *obj, const char *name,
    struct elf_symbol *out)
{
	ENTRY e = {.key = (char *)name, NULL}, *ep;
	int n;

	if (name == NULL)
		return false;
	if (obj->flags & ELF_SYMTAB_F) {
		n = hsearch_r(e, FIND, &ep, &obj->cache.symtab);
		if (n != 0) {
			memcpy(out, ep->data, sizeof(*out));
			return true;
		}
	}
	if (obj->flags & ELF_DYNSYM_F) {
		n = hsearch_r(e, FIND, &ep, &obj->cache.dynsym);
		if (n != 0) {
			memcpy(out, ep->data, sizeof(*out));
			return true;
		}
	}
	return false;
}

uint16_t
elf_machine(struct elfobj *obj)
{

	switch(obj->e_class) {
	case elfclass32:
		return obj->ehdr32->e_machine;
	case elfclass64:
		return obj->ehdr64->e_machine;
	default:
		return ~0;
	}
	return ~0;
}

uint64_t
elf_entry_point(struct elfobj *obj)
{

	return obj->entry_point;
}

uint32_t
elf_type(struct elfobj *obj)
{

	return obj->type;
}

void *
elf_offset_pointer(elfobj_t *obj, uint64_t off)
{

	if (off >= obj->size)
		return NULL;

	return (void *)((uint8_t *)&obj->mem[off]);
}

void *
elf_section_pointer(elfobj_t *obj, void *shdr)
{
	union {
		Elf32_Shdr *shdr32;
		Elf64_Shdr *shdr64;
	} e;

	switch(obj->e_class) {
	case elfclass32:
		e.shdr32 = (Elf32_Shdr *)shdr;
		if (e.shdr32->sh_offset >= obj->size)
			return NULL;
		return (void *)((uint8_t *)&obj->mem[e.shdr32->sh_offset]);
	case elfclass64:
		e.shdr64 = (Elf64_Shdr *)shdr;
		if (e.shdr64->sh_offset >= obj->size)
			return NULL;
		return (void *)((uint8_t *)&obj->mem[e.shdr64->sh_offset]);
	}
	return NULL;
}

#if 0
Ignore this function, it has been totally re-written in a way that makes
sense for another branch (ul_exec branch), this code is wrong and bad.
#endif
bool
elf_map_loadable_segments(struct elfobj *obj, struct elf_mapping *mapping,
    elf_error_t *error)
{
	elf_segment_iterator_t p_iter;
	struct elf_segment segment;

	memset(mapping, 0, sizeof(*mapping));

	elf_segment_iterator_init(obj, &p_iter);
	while (elf_segment_iterator_next(&p_iter, &segment) == ELF_ITER_OK) {
		uintptr_t map_addr;
		size_t map_size;
		uint64_t map_off;

		if (segment.type != PT_LOAD)
			continue;
		map_addr = segment.vaddr & ~0xfff;
		map_size = ROUNDUP(segment.memsz, 0x1000);
		mapping->mem[mapping->index] = mmap((void *)map_addr,
		    map_size, PROT_READ|PROT_WRITE|PROT_EXEC,
		    MAP_FIXED|MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);

		if (mapping->mem[mapping->index] == MAP_FAILED) {
			return elf_error_set(error, "mmap: %s", strerror(errno));
		}

		map_off = segment.vaddr & 0xfff;
		memcpy(&mapping->mem[mapping->index][map_off],
		    &obj->mem[segment.offset], segment.filesz);

		mapping->flags = segment.flags;
		if (mprotect(mapping->mem[mapping->index], map_size,
		    segment.flags) < 0) {
			return elf_error_set(error, "mprotect: %s",
			    strerror(errno));
		}
		mapping->index++;
	}
	return true;
}

#define MAX_SO_COUNT 1024

/*
 * The shared object iterator is the most sophisticated of all iterators.
 * It uses the ld.so.cache to quickly resolve shared library basenames to
 * complete paths; similarly to how the dynamic linker works.
 */
bool
elf_shared_object_iterator_init(struct elfobj *obj,
    struct elf_shared_object_iterator *iter, const char *cache_path,
    uint32_t flags, elf_error_t *error)
{
	const char *cache_file = cache_path == NULL ? CACHE_FILE : cache_path;

	/*
	 * This list is only used for recursive resolution
	 * e.g. ELF_SO_RESOLVE_ALL_F
	 */
	LIST_INIT(&iter->yield_list);
	/*
	 * This list maintains the backing of .so paths
	 * needed by the yield_cache in ldso_insert_yield_entry.
	 */
	LIST_INIT(&iter->malloc_list);

	iter->flags = flags;
	iter->cache_flags = 0;
	iter->index = 0;
	iter->obj = obj;

	if ((flags & ELF_SO_RESOLVE_F) == 0 &&
	    (flags & ELF_SO_RESOLVE_ALL_F) == 0)
		goto finish;
	if (flags & ELF_SO_RESOLVE_ALL_F) {
		iter->flags |= ELF_SO_RESOLVE_F;
		memset(&iter->yield_cache, 0, sizeof(struct hsearch_data));
		if (hcreate_r(MAX_SO_COUNT, &iter->yield_cache) == 0)
			return elf_error_set(error, "hcreate_r: %s",
			    strerror(errno));
	}
	iter->fd = open(cache_file, O_RDONLY);
	if (iter->fd < 0) {
		return elf_error_set(error, "open %s: %s", CACHE_FILE,
		    strerror(errno));
	}
	if (fstat(iter->fd, &iter->st) < 0) {
		return elf_error_set(error, "fstat %s: %s", CACHE_FILE,
		    strerror(errno));
	}
	iter->mem = mmap(NULL, iter->st.st_size, PROT_READ, MAP_PRIVATE,
	    iter->fd, 0);
	if (iter->mem == MAP_FAILED) {
		return elf_error_set(error, "mmap %s: %s", CACHE_FILE,
		    strerror(errno));
	}
	iter->cache = iter->mem;
	/*
	 * Handle 3 formats:
	 * old libc6/glibc2.0/2.1 format
	 * old format with the new format in it
	 * only the new format
	 */
	if (memcmp(iter->mem, CACHEMAGIC, strlen(CACHEMAGIC))) {
		/*
		 * old format
		 */
		size_t offset;

		iter->cache_flags |= ELF_LDSO_CACHE_OLD;
		offset = ALIGN_CACHE(sizeof(struct cache_file)
		    + iter->cache->nlibs * sizeof(struct file_entry));
		iter->cache_new = (struct cache_file_new *)
		    ((char *)iter->cache + offset);
		if ((size_t)iter->st.st_size < (offset + sizeof(struct cache_file_new))
		    || memcmp(iter->cache_new->magic, CACHEMAGIC_VERSION_NEW,
		    strlen(CACHEMAGIC_VERSION_NEW)) != 0) {
			/*
			 * Only the old format is set.
			 */
			iter->cache_new = (void *)-1;
		} else {
			/*
			 * old format and new format are both set
			 */
			iter->cache_flags |= ELF_LDSO_CACHE_NEW;
		}
	} else if (memcmp(iter->mem, CACHEMAGIC_VERSION_NEW,
	    strlen(CACHEMAGIC_VERSION_NEW)) == 0) {
		/*
		 * New format only
		 */
		iter->cache_new = iter->mem;
		iter->cache_flags |= ELF_LDSO_CACHE_NEW;
	}

	if (iter->cache_flags & ELF_LDSO_CACHE_NEW) {
		iter->cache_data = (char *)iter->cache_new;
		iter->cache_size = (char *)iter->cache + iter->st.st_size -
		    iter->cache_data;
		DEBUG_LOG("using new cache, size: %lu\n", iter->cache_size);
	} else {
		iter->cache_data =
		    (char *)&iter->cache->libs[iter->cache->nlibs];
		iter->cache_size = (char *)iter->cache + iter->st.st_size -
		    iter->cache_data;
		DEBUG_LOG("using old cache, size: %lu\n", iter->cache_size);
	}
	/*
	 * Linked list containing DT_NEEDED entries (basenames)
	 */
finish:
	iter->current = LIST_FIRST(&obj->list.shared_objects);
	return true;
}

elf_iterator_res_t
elf_shared_object_iterator_next(struct elf_shared_object_iterator *iter,
    struct elf_shared_object *entry, elf_error_t *error)
{
	bool result;

	if (iter->current == NULL && LIST_EMPTY(&iter->yield_list)) {
		ldso_cleanup(iter);
		return ELF_ITER_DONE;
	}
	/*
	 * If the ELF_SO_RESOLVE_F flag is NOT set, then we are only
	 * interested in getting the basenames of the shared objects in
	 * iter->obj's DT_NEEDED entries.
	 */
	if ((iter->flags & ELF_SO_RESOLVE_F) == 0)
		goto next_basename;

	/*
	 * If the ELF_SO_RESOLVE_ALL_F flag is set then we are wanting
	 * to fully resolve each basename to path using ldso.cache, and
	 * recursively resolve each dependency for every object in the
	 * DT_NEEDED entries.
	 */
	if (iter->flags & ELF_SO_RESOLVE_ALL_F) {
		/*
		 * Yield each item in the yield list when its not empty.
		 */
		if (LIST_EMPTY(&iter->yield_list) == 0) {
			iter->yield = LIST_FIRST(&iter->yield_list);
			entry->path = iter->yield->path;
			entry->basename = iter->yield->basename;
			LIST_REMOVE(iter->yield, _linkage);
			free(iter->yield);
			return ELF_ITER_OK;
		}
		/*
		 * Otherwise move on to resolving the next dependencies for
		 * iter->current->basename.
		 */
		result = ldso_recursive_cache_resolve(iter, iter->current->basename);
		if (!result) {
			elf_error_set(error, "ldso_recursive_cache_resolve(%p, %s) failed\n",
			    iter, iter->current->basename);
			goto err;
		}
		
		if (result) {
			/*if dependency path was not found in ld.so.cache, just set path name as NULL and get next basename*/
			entry->path = (char *)ldso_cache_bsearch(iter, iter->current->basename);
			entry->basename = iter->current->basename;
			iter->current = LIST_NEXT(iter->current, _linkage);
			
			if (entry->path == NULL) {	
				return ELF_ITER_NOTFOUND;
			}
			if (ldso_insert_yield_cache(iter, entry->path) == false) {
				elf_error_set(error, "ldso_insert_yield_cache failed");
				goto err;
			}
			return ELF_ITER_OK;
		}
	}
	entry->path = (char *)ldso_cache_bsearch(iter, iter->current->basename);
	if (entry->path == NULL) {
		elf_error_set(error, "ldso_cache_bsearch(%p, %s) failed",
		    iter, iter->current->basename);
		goto err;
	}

next_basename:
	entry->basename = iter->current->basename;
	iter->current = LIST_NEXT(iter->current, _linkage);
	return ELF_ITER_OK;
err:
	ldso_cleanup(iter);
	return ELF_ITER_ERROR;
}

bool
elf_relocation_iterator_init(struct elfobj *obj,
    struct elf_relocation_iterator *iter)
{
	unsigned int i;

	iter->obj = obj;
	iter->index = 0;

	LIST_INIT(&iter->list);
	if (obj->e_class == elfclass32) {
		Elf32_Shdr *shdr32 = obj->shdr32;
		/*
		 * We build a linked list which contains the relocation sections
		 * that we must parse.
		 */
		for (i = 0; i <	obj->section_count; i++) {
			unsigned int type = shdr32[i].sh_type;

			if (type == SHT_REL || type == SHT_RELA) {
				struct elf_rel_helper_node *n =
				    malloc(sizeof(*n));

				if (n == NULL)
					return false;

				n->size = shdr32[i].sh_size;
				if (type == SHT_REL) {
					n->rel32 = elf_section_pointer(obj,
					    &shdr32[i]);
					if (n->rel32 == NULL)
						return false;
					n->addend = false;
				} else if (type == SHT_RELA) {
					n->rela32 = elf_section_pointer(obj,
					    &shdr32[i]);
					if (n->rela32 == NULL)
						return false;
					n->addend = true;
				}
				n->section_name =
				    (char *)elf_section_name_by_index(obj, i);
				LIST_INSERT_HEAD(&iter->list, n, _linkage);
			}
		}
	} else if (obj->e_class == elfclass64) {
		Elf64_Shdr *shdr64 = obj->shdr64;

		for (i = 0; i < obj->section_count; i++) {
			unsigned int type = shdr64[i].sh_type;

			if (type == SHT_REL || type == SHT_RELA) {
				struct elf_rel_helper_node *n =
				    malloc(sizeof(*n));
				if (n == NULL)
					return false;

				n->size = shdr64[i].sh_size;
				if (type == SHT_REL) {
					n->rel64 = elf_section_pointer(obj,
					    &shdr64[i]);
					if (n->rel64 == NULL)
						return false;
					n->addend = false;
				} else if (type == SHT_RELA) {
					n->rela64 = elf_section_pointer(obj,
					    &shdr64[i]);
					if (n->rela64 == NULL)
						return false;
					n->addend = true;
				}
				n->section_name =
				    (char *)elf_section_name_by_index(obj, i);
				LIST_INSERT_HEAD(&iter->list, n, _linkage);
			}
		}
	} else {
		/*
		 * Should never get here.
		 */
		return false;
	}
	iter->head = iter->current = LIST_FIRST(&iter->list);
	return true;
}

elf_iterator_res_t
elf_relocation_iterator_next(struct elf_relocation_iterator *iter,
    struct elf_relocation *entry)
{
	struct elf_rel_helper_node *current;
	struct elfobj *obj;
	int which = SHT_NULL;
begin:
	obj = iter->obj;
	current = iter->current;

	if (current == NULL || LIST_EMPTY(&iter->list)) {
		struct elf_rel_helper_node *next;

		LIST_FOREACH_SAFE(current, &iter->list, _linkage, next)
			free(current);
		return ELF_ITER_DONE;
	}
	/*
	 * If we're dealing sections rela.plt, rel.plt
	 * rela.dyn or rel.dyn, then we need to look up
	 * symbol indexes in the dynamic symbol table..
	 * UNLESS this is a statically linked executable
	 * in which case there may still be a plt/got but
	 * there will not be a .dynsym.
	 */
	which = SHT_SYMTAB;
	if (strstr(current->section_name, ".plt") ||
	    strstr(current->section_name, ".dynamic")) {
		if (obj->flags & ELF_DYNAMIC_F)
			which = SHT_DYNSYM;
	}
	if (iter->obj->e_class == elfclass32) {
		unsigned int i = iter->index++;
		const size_t entsz = current->addend ? sizeof(Elf32_Rela) :
		    sizeof(Elf32_Rel);

		if (i >= iter->current->size / entsz) {
			iter->index = 0;
			iter->current = LIST_NEXT(iter->current, _linkage);
			goto begin;
		}
		if (current->addend == true) {
			struct elf_symbol symbol;
			const unsigned int symidx =
			    ELF32_R_SYM(current->rela32[i].r_info);

			if (elf_symbol_by_index(obj, symidx, &symbol, which) == false)
				goto err;

			entry->offset = current->rela32[i].r_offset;
			entry->type = ELF32_R_TYPE(current->rela32[i].r_info);
			entry->addend = current->rela32[i].r_addend;
			entry->symname = (char *)symbol.name;
			entry->shdrname = current->section_name;
			return ELF_ITER_OK;
		} else {
			struct elf_symbol symbol;
			const unsigned int symidx =
			    ELF32_R_SYM(current->rel32[i].r_info);

			if (elf_symbol_by_index(obj, symidx, &symbol, which) == false)
				goto err;

			entry->offset = current->rel32[i].r_offset;
			entry->type = ELF32_R_TYPE(current->rel32[i].r_info);
			entry->addend = 0;
			entry->symname = (char *)symbol.name;
			entry->shdrname = current->section_name;
			return ELF_ITER_OK;
		}
	} else if (iter->obj->e_class == elfclass64) {
		unsigned int i = iter->index++;
		const size_t entsz = current->addend ? sizeof(Elf64_Rela) :
		    sizeof(Elf64_Rel);

		if (i >= iter->current->size / entsz) {
			iter->index = 0;
			iter->current = LIST_NEXT(iter->current, _linkage);
			goto begin;
		}
		if (current->addend == true) {
			struct elf_symbol symbol;
			const unsigned int symidx =
			    ELF64_R_SYM(current->rela64[i].r_info);

			if (elf_symbol_by_index(obj, symidx, &symbol, which) == false)
				goto err;

			entry->offset = current->rela64[i].r_offset;
			entry->type = ELF64_R_TYPE(current->rela64[i].r_info);
			entry->addend = current->rela64[i].r_addend;
			entry->symname = (char *)symbol.name;
			entry->shdrname = current->section_name;
			return ELF_ITER_OK;
		} else {
			struct elf_symbol symbol;
			const unsigned int symidx =
			    ELF64_R_SYM(current->rel64[i].r_info);

			if (elf_symbol_by_index(obj, symidx, &symbol, which) == false)
				goto err;
			entry->offset = current->rel64[i].r_offset;
			entry->type = ELF64_R_TYPE(current->rel64[i].r_offset);
			entry->addend = 0;
			entry->symname = (char *)symbol.name;
			entry->shdrname = current->section_name;
			return ELF_ITER_OK;
		}

	}
	/*
	 * Should never get here.
	 */
err:
	return ELF_ITER_ERROR;
}

void
elf_symtab_iterator_init(struct elfobj *obj, struct elf_symtab_iterator *iter)
{

	iter->current = LIST_FIRST(&obj->list.symtab);
	return;
}

elf_iterator_res_t
elf_symtab_iterator_next(struct elf_symtab_iterator *iter,
    struct elf_symbol *symbol)
{

	if (iter->current == NULL)
		return ELF_ITER_DONE;
	memcpy(symbol, iter->current, sizeof(*symbol));
	iter->current = LIST_NEXT(iter->current, _linkage);
	return ELF_ITER_OK;
}

void
elf_dynsym_iterator_init(struct elfobj *obj, struct elf_dynsym_iterator *iter)
{

	iter->current = LIST_FIRST(&obj->list.dynsym);
	return;
}

elf_iterator_res_t
elf_dynsym_iterator_next(struct elf_dynsym_iterator *iter,
    struct elf_symbol *symbol)
{

	if (iter->current == NULL)
		return ELF_ITER_DONE;
	memcpy(symbol, iter->current, sizeof(*symbol));
	iter->current = LIST_NEXT(iter->current, _linkage);
	return ELF_ITER_OK;
}

bool
elf_plt_by_name(struct elfobj *obj, const char *name, struct elf_plt *entry)
{
	ENTRY e = {(char *)name, NULL};
	ENTRY *ep;

	if (hsearch_r(e, FIND, &ep, &obj->cache.plt) != 0) {
		memcpy(entry, ep->data, sizeof(*entry));
		return true;
	}
	return false;
}

void
elf_plt_iterator_init(struct elfobj *obj, struct elf_plt_iterator *iter)
{

	iter->current = LIST_FIRST(&obj->list.plt);
	return;
}

elf_iterator_res_t
elf_plt_iterator_next(struct elf_plt_iterator *iter, struct elf_plt *entry)
{

	if (iter->current == NULL)
		return ELF_ITER_DONE;
	memcpy(entry, iter->current, sizeof(*entry));
	iter->current = LIST_NEXT(iter->current, _linkage);
	return ELF_ITER_OK;
}


void
elf_dynamic_iterator_init(struct elfobj *obj, struct elf_dynamic_iterator *iter)
{

	iter->obj = obj;
	iter->index = 0;
	return;
}

elf_iterator_res_t
elf_dynamic_iterator_next(struct elf_dynamic_iterator *iter,
    struct elf_dynamic_entry *entry)
{
	unsigned int i = iter->index;

	switch(iter->obj->e_class) {
	case elfclass32:
		if (iter->obj->dynamic32 == NULL)
			return ELF_ITER_DONE;
		if (iter->obj->dynamic32[i].d_tag == DT_NULL)
			return ELF_ITER_DONE;
		entry->tag = iter->obj->dynamic32[i].d_tag;
		entry->value = iter->obj->dynamic32[i].d_un.d_val;
		break;
	case elfclass64:
		if (iter->obj->dynamic64 == NULL)
			return ELF_ITER_DONE;
		if (iter->obj->dynamic64[i].d_tag == DT_NULL)
			return ELF_ITER_DONE;
		entry->tag = iter->obj->dynamic64[i].d_tag;
		entry->value = iter->obj->dynamic64[i].d_un.d_val;
		break;
	default:
		return ELF_ITER_ERROR;
	}
	iter->index++;
	return ELF_ITER_OK;
}

bool
elf_note_iterator_init(struct elfobj *obj, struct elf_note_iterator *iter)
{

	iter->obj = obj;
	iter->index = 0;
	switch(iter->obj->e_class) {
	case elfclass32:
		iter->note32 = iter->obj->note32;
		break;
	case elfclass64:
		iter->note64 = iter->obj->note64;
		break;
	default:
		return false;
	}
	return true;
}

elf_iterator_res_t
elf_note_iterator_next(struct elf_note_iterator *iter,
    struct elf_note_entry *entry)
{
	size_t entry_len;

	if (iter->index >= iter->obj->note_size)
		return ELF_ITER_DONE;

	switch(iter->obj->e_class) {
	case elfclass32:
		if (iter->note32 == NULL)
			return ELF_ITER_DONE;
		entry->mem = ELFNOTE_DESC(iter->note32);
		entry->size = iter->note32->n_descsz;
		entry->type = iter->note32->n_type;
		entry_len = ELFNOTE_ALIGN(iter->note32->n_descsz +
		    iter->note32->n_namesz + sizeof(long));
		iter->note32 = ELFNOTE32_NEXT(iter->note32);
		break;
	case elfclass64:
		if (iter->note64 == NULL)
			return ELF_ITER_DONE;
		entry->mem = ELFNOTE_DESC(iter->note64);
		entry->size = iter->note64->n_descsz;
		entry->type = iter->note64->n_type;
		entry_len = ELFNOTE_ALIGN(iter->note64->n_descsz +
		    iter->note64->n_namesz + sizeof(long));
		iter->note64 = ELFNOTE64_NEXT(iter->note64);
		break;
	default:
		return ELF_ITER_ERROR;
	}
	iter->index += entry_len;
	return ELF_ITER_OK;
}

void
elf_segment_iterator_init(struct elfobj *obj, struct elf_segment_iterator *iter)
{

	iter->index = 0;
	iter->obj = obj;
	return;
}

elf_iterator_res_t
elf_segment_iterator_next(struct elf_segment_iterator *iter,
    struct elf_segment *segment)
{
	elfobj_t *obj = iter->obj;

	if (iter->index >= obj->segment_count)
		return ELF_ITER_DONE;

	switch(obj->e_class) {
	case elfclass32:
		if (obj->phdr32 == NULL)
			return ELF_ITER_DONE;
		segment->type = obj->phdr32[iter->index].p_type;
		segment->flags = obj->phdr32[iter->index].p_flags;
		segment->offset = obj->phdr32[iter->index].p_offset;
		segment->paddr = obj->phdr32[iter->index].p_paddr;
		segment->vaddr = obj->phdr32[iter->index].p_vaddr;
		segment->filesz = obj->phdr32[iter->index].p_filesz;
		segment->memsz = obj->phdr32[iter->index].p_memsz;
		segment->align = obj->phdr32[iter->index].p_align;
		break;
	case elfclass64:
		if (obj->phdr64 == NULL)
			return ELF_ITER_DONE;
		segment->type = obj->phdr64[iter->index].p_type;
		segment->flags = obj->phdr64[iter->index].p_flags;
		segment->offset = obj->phdr64[iter->index].p_offset;
		segment->paddr = obj->phdr64[iter->index].p_paddr;
		segment->vaddr = obj->phdr64[iter->index].p_vaddr;
		segment->filesz = obj->phdr64[iter->index].p_filesz;
		segment->memsz = obj->phdr64[iter->index].p_memsz;
		segment->align = obj->phdr64[iter->index].p_align;
		break;
	default:
		return ELF_ITER_ERROR;
	}
	iter->index++;
	return ELF_ITER_OK;
}

void
elf_section_iterator_init(struct elfobj *obj, struct elf_section_iterator *iter)
{

	iter->index = 0;
	iter->obj = obj;
	return;
}

const char *
elf_pltgot_flag_string(uint32_t flags)
{

	switch(flags) {
	case ELF_PLTGOT_RESERVED_DYNAMIC_F:
		return "DYNAMIC SEGMENT";
	case ELF_PLTGOT_RESERVED_LINKMAP_F:
		return "LINKMAP POINTER";
	case ELF_PLTGOT_RESERVED_DL_RESOLVE_F:
		return "__DL_RESOLVE POINTER";
	case ELF_PLTGOT_PLT_STUB_F:
		return "PLT STUB";
	case ELF_PLTGOT_RESOLVED_F:
		return "RESOLVED";
	default:
		return "";
	}
	return "";
}

void
elf_pltgot_iterator_init(struct elfobj *obj, struct elf_pltgot_iterator *iter)
{

	iter->index = 0;
	iter->obj = obj;
	if (iter->obj->dynseg.pltgot.addr == 0) {
		iter->pltgot = NULL;
	} else {
		iter->pltgot = elf_address_pointer(iter->obj, iter->obj->dynseg.pltgot.addr);
	}
	iter->wordsize = iter->obj->arch == i386 ? 4 : 8;
	iter->gotsize = (iter->wordsize * 3) + obj->dynsym_count * iter->wordsize;
	return;
}

elf_iterator_res_t
elf_pltgot_iterator_next(struct elf_pltgot_iterator *iter, struct elf_pltgot_entry *entry)
{
	struct elf_section section;

	entry->flags = 0;

	if (iter->pltgot == NULL)
		return ELF_ITER_DONE;

	switch(iter->index) {
	case 0:
		entry->flags = ELF_PLTGOT_RESERVED_DYNAMIC_F;
		break;
	case 1:
		entry->flags = ELF_PLTGOT_RESERVED_LINKMAP_F;
		break;
	case 2:
		entry->flags = ELF_PLTGOT_RESERVED_DL_RESOLVE_F;
	default:
		break;
	}

	if (iter->obj->arch == i386) {
		uint32_t *ptr = iter->pltgot;

		entry->value = ptr[iter->index];
	} else if (iter->obj->arch == x64) {
		uint64_t *ptr = iter->pltgot;

		entry->value = ptr[iter->index];
	}
	if (elf_section_by_name(iter->obj, ".plt", &section) == true) {
		if (entry->value >= section.address &&
		    entry->value < section.address + section.size)
			entry->flags = ELF_PLTGOT_PLT_STUB_F;
	}
	entry->offset = iter->obj->dynseg.pltgot.addr + iter->wordsize * iter->index;
	if ((iter->index * iter->wordsize) > iter->gotsize) {
		return ELF_ITER_DONE;
	}
	iter->index++;
	return ELF_ITER_OK;
}

/*
 * We don't use obj->sections, since that is sorted. We re-create an 'struct
 * elf_section' for each entry, and print them in the order the actual shdrs
 * are listed in the binary.
 */
elf_iterator_res_t
elf_section_iterator_next(struct elf_section_iterator *iter,
    struct elf_section *section)
{
	elfobj_t *obj = iter->obj;

	if (iter->index >= obj->section_count)
		return ELF_ITER_DONE;

	switch(obj->e_class) {
	case elfclass32:
		if (obj->shdr32 == NULL || obj->shstrtab == NULL)
			return ELF_ITER_DONE;
		section->name = &obj->shstrtab[obj->shdr32[iter->index].sh_name];
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
	case elfclass64:
		if (obj->shdr64 == NULL || obj->shstrtab == NULL)
			return ELF_ITER_DONE;
		section->name = &obj->shstrtab[obj->shdr64[iter->index].sh_name];
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
	iter->index++;
	return ELF_ITER_OK;
}

/*
 * Secure ELF loader.
 */
bool
elf_open_object(const char *path, struct elfobj *obj, uint64_t load_flags,
    elf_error_t *error)
{
	int fd;
	uint32_t i;
	unsigned int open_flags = O_RDONLY;
	unsigned int mmap_perms = PROT_READ|PROT_WRITE;
	unsigned int mmap_flags = MAP_PRIVATE;
	uint8_t *mem;
	uint8_t e_class;
	uint16_t e_machine;
	struct stat st;
	size_t section_count;
	bool text_found = false, data_found = false;
	bool __strict = false;

	/*
	 * We count on this being initialized for various sanity checks.
	 */
	memset(obj, 0, sizeof(*obj));

	if (load_flags & ELF_LOAD_F_MODIFY) {
		mmap_flags = MAP_SHARED;
	}
	if (load_flags & ELF_LOAD_F_STRICT) {
		__strict = true;
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
	obj->mem = mem;

	if (memcmp(mem, "\x7f\x45\x4c\x46", 4) != 0) {
		elf_error_set(error, "invalid ELF file magic", strerror(errno));
		goto err;
	}

	obj->type = *(uint16_t *)((uint8_t *)&mem[16]);
	e_machine = *(uint16_t *)((uint8_t *)&mem[18]);
	e_class = mem[EI_CLASS];
	switch(e_machine) {
	case EM_X86_64:
		obj->arch = x64;
		break;
	case EM_386:
		obj->arch = i386;
		break;
	default:
		obj->arch = unsupported;
		break;
	}
	/*
	 * Set the ELF header pointers as contingent upon the supported arch
	 * types. Also enforce some rudimentary security checks/sanity checks
	 * to prevent possible invalid memory derefs down the road.
	 * We must make sure that we are able to load any binary the kernel can
	 * (unless in strict mode) and then we will ultimately reconstruct
	 * the data that is normally only accessible by sections, and store them
	 * within our internal data structures.
	 */
	switch(e_class) {
	case ELFCLASS32:
		obj->e_class = elfclass32;
		obj->ehdr32 = (Elf32_Ehdr *)mem;
		if (obj->ehdr32->e_shnum > 0)
			obj->flags |= ELF_SHDRS_F;
		if (obj->ehdr32->e_phnum > 0)
			obj->flags |= ELF_PHDRS_F;
		if (obj->ehdr32->e_shnum > MAX_VALID_SHNUM)
			obj->anomalies |= INVALID_F_SHNUM;

		if (obj->ehdr32->e_phoff > obj->size - sizeof(Elf32_Phdr) - 1) {
				elf_error_set(error, "invalid e_phoff: %lx", obj->ehdr32->e_phoff);
				goto err;
		}
		if (obj->ehdr32->e_shoff > obj->size - (sizeof(Elf32_Shdr) - 1)) {
			if (__strict) {
				elf_error_set(error, "invalid e_shoff: %lx", obj->ehdr32->e_shoff);
				goto err;
			}
			obj->anomalies |= INVALID_F_SHOFF;
		}
		/*
		 * We can trust e_phoff cuz its necessary for loading and we
		 * would have exited by now.
		 */
		obj->phdr32 = (Elf32_Phdr *)&mem[obj->ehdr32->e_phoff];
		/*
		 * Any headers not necessary for loaded should only be loaded if
		 * they have valid headers. We can reconstruct what they had in them
		 * later on using the program headers.
		 */
		if ((obj->anomalies & INVALID_F_SHOFF) == 0)
			obj->shdr32 = (Elf32_Shdr *)&mem[obj->ehdr32->e_shoff];

		obj->entry_point = obj->ehdr32->e_entry;
		obj->type = obj->ehdr32->e_type;
		obj->segment_count = obj->ehdr32->e_phnum;
		obj->flags |= (obj->ehdr32->e_shnum > 0 ? ELF_SHDRS_F : 0);

		if (obj->ehdr32->e_shstrndx > obj->ehdr32->e_shnum - 1) {
			if (__strict) {
				elf_error_set(error, "invalid e_shstrndx: %u\n",
				    obj->ehdr32->e_shstrndx);
				goto err;
			}
			obj->anomalies |= INVALID_F_SHSTRNDX;
		}
		if (obj->shdr32[obj->ehdr32->e_shstrndx].sh_offset >
		    obj->size - sizeof(Elf32_Shdr) - 1) {
			if (__strict) {
				elf_error_set(error,
				    "invalid section header string table offset: %lx",
				    obj->shdr32[obj->ehdr32->e_shstrndx].sh_offset);
				goto err;
			}
			obj->anomalies |= INVALID_F_SHOFFSET;
		}

		obj->shstrtab =
		    (char *)&mem[obj->shdr32[obj->ehdr32->e_shstrndx].sh_offset];

		obj->section_count = section_count = obj->ehdr32->e_shnum;

		if (obj->ehdr32->e_type != ET_REL) {
			if ((obj->ehdr32->e_phoff +
			     (obj->ehdr32->e_phnum * sizeof(Elf32_Phdr))) > obj->size) {
				elf_error_set(error, "unsafe phdr values");
				goto err;
			}
		}
		if ((obj->ehdr32->e_shoff +
		    (obj->ehdr32->e_shnum * sizeof(Elf32_Shdr))) > obj->size) {
			if (__strict) {
				elf_error_set(error, "unsafe shdr value");
				goto err;
			}
			obj->anomalies |= INVALID_F_SH_HEADERS;
		}
		if (obj->ehdr32->e_shentsize != sizeof(Elf32_Shdr)) {
			if (__strict) {
				elf_error_set(error, "invalid shentsize: %u",
				    obj->ehdr32->e_shentsize);
				goto err;
			}
			obj->anomalies |= INVALID_F_SHENTSIZE;
		}
		if (obj->ehdr32->e_type != ET_REL) {
			if (obj->ehdr32->e_phentsize != sizeof(Elf32_Phdr)) {
				elf_error_set(error, "invalid e_phentsize: %u",
				    obj->ehdr32->e_phentsize);
				goto err;
			}
		}
		if (obj->ehdr32->e_type == ET_REL)
			break;
		for (i = 0; i < obj->ehdr32->e_phnum; i++) {
			if (obj->phdr32[i].p_type == PT_NOTE) {
				obj->flags |= ELF_NOTE_F;
				obj->note32 = (Elf32_Nhdr *)&obj->mem[obj->phdr32[i].p_offset];
				obj->note_size = obj->phdr32[i].p_filesz;
			} else if (obj->phdr32[i].p_type == PT_DYNAMIC) {
				obj->flags |= ELF_DYNAMIC_F;
				obj->dynamic32 = (Elf32_Dyn *)&obj->mem[obj->phdr32[i].p_offset];
				obj->dynamic_size = obj->phdr32[i].p_filesz;
			} else if (obj->phdr32[i].p_type == PT_GNU_EH_FRAME) {
				obj->eh_frame = &obj->mem[obj->phdr32[i].p_offset];
				obj->eh_frame_size = obj->phdr32[i].p_filesz;
			} else if (obj->phdr32[i].p_type == PT_LOAD && obj->phdr32[i].p_offset == 0) {
				obj->pt_load[obj->load_count].flag |= ELF_PT_LOAD_TEXT_F;
				text_found = true;
				memcpy(&obj->pt_load[obj->load_count++].phdr32, &obj->phdr32[i],
				    sizeof(Elf32_Phdr));
			} else if (obj->phdr32[i].p_type == PT_LOAD && text_found == false) {
				if ((obj->phdr32[i].p_flags & (PF_R|PF_X)) == (PF_R | PF_X)) {
					obj->pt_load[obj->load_count].flag |= ELF_PT_LOAD_TEXT_F;
					text_found = true;
					memcpy(&obj->pt_load[obj->load_count++].phdr32,
					    &obj->phdr32[i], sizeof(Elf32_Phdr));
				}
			} else if (obj->phdr32[i].p_type == PT_LOAD) {
				if (data_found == true) {
					obj->pt_load[obj->load_count].flag |= ELF_PT_LOAD_MISC_F;
					memcpy(&obj->pt_load[obj->load_count++].phdr32,
					    &obj->phdr32[i], sizeof(Elf32_Phdr));
				} else {
					obj->pt_load[obj->load_count].flag |= ELF_PT_LOAD_DATA_F;
					data_found = true;
					memcpy(&obj->pt_load[obj->load_count++].phdr32,
					    &obj->phdr32[i], sizeof(Elf32_Phdr));
				}
			}
		}
		break;
	case ELFCLASS64:
		obj->e_class = elfclass64;
		obj->ehdr64 = (Elf64_Ehdr *)mem;

		if (obj->ehdr64->e_shnum > 0)
			obj->flags |= ELF_SHDRS_F;
		if (obj->ehdr64->e_phnum > 0)
			obj->flags |= ELF_PHDRS_F;

		if (obj->ehdr64->e_phoff > obj->size - sizeof(Elf64_Phdr) - 1) {
			elf_error_set(error, "invalid e_phoff: %lx",
			    obj->ehdr64->e_phoff);
			goto err;
		}
		if (obj->ehdr64->e_shoff > obj->size - (sizeof(Elf64_Shdr) - 1)) {
			if (__strict) {
				elf_error_set(error,
				    "invalid e_shoff: %lx", obj->ehdr64->e_shoff);
				goto err;
			}
			obj->anomalies |= INVALID_F_SHOFF;
		}
		/*
		 * We can trust e_phoff cuz its necessary for loading and
		 * we would have exited by now if it was a bad value.
		 */
		obj->phdr64 = (Elf64_Phdr *)&mem[obj->ehdr64->e_phoff];
		/*
		 * Again: any headers not necessary for loading are only
		 * loaded if they are valid.
		 */
		if ((obj->anomalies & INVALID_F_SHOFF) == 0)
			obj->shdr64 = (Elf64_Shdr *)&mem[obj->ehdr64->e_shoff];

		obj->entry_point = obj->ehdr64->e_entry;
		obj->type = obj->ehdr64->e_type;
		obj->segment_count = obj->ehdr64->e_phnum;
		obj->flags |= (obj->ehdr64->e_shnum > 0 ? ELF_SHDRS_F : 0);

		if (obj->ehdr64->e_shstrndx > obj->ehdr64->e_shnum - 1) {
			if (__strict) {
				elf_error_set(error, "invalid e_shstrndx: %lu",
				     obj->ehdr64->e_shstrndx);
				goto err;
			}
			obj->anomalies |= INVALID_F_SHSTRNDX;
		}
		if (obj->shdr64[obj->ehdr64->e_shstrndx].sh_offset >
		    obj->size - sizeof(Elf64_Shdr) - 1) {
			if (__strict ) {
				elf_error_set(error, "invalid section header string table offset: %lx",
				    obj->shdr64[obj->ehdr64->e_shstrndx].sh_offset);
				goto err;
			}
			obj->anomalies |= INVALID_F_SHOFFSET;
		}

		obj->shstrtab =
		    (char *)&mem[obj->shdr64[obj->ehdr64->e_shstrndx].sh_offset];

		obj->section_count = section_count = obj->ehdr64->e_shnum;

		if (obj->ehdr64->e_type != ET_REL) {
			if ((obj->ehdr64->e_phoff +
			    (obj->ehdr64->e_phnum * sizeof(Elf64_Phdr))) > obj->size) {
				elf_error_set(error, "unsafe phdr values");
				goto err;
			}
		}
		if ((obj->ehdr64->e_shoff +
		    (obj->ehdr64->e_shnum * sizeof(Elf64_Shdr))) > obj->size) {
			if (__strict) {
				elf_error_set(error, "unsafe shdr values");
				goto err;
			}
			obj->anomalies |= INVALID_F_SH_HEADERS;
		}
		if (obj->ehdr64->e_shentsize != sizeof(Elf64_Shdr)) {
			if (__strict) {
				elf_error_set(error, "invalid_e_shentsize: %u",
				    obj->ehdr64->e_shentsize);
				goto err;
			}
			obj->anomalies |= INVALID_F_SHENTSIZE;
		}
		if (obj->ehdr64->e_type != ET_REL) {
			if (obj->ehdr64->e_phentsize != sizeof(Elf64_Phdr)) {
				elf_error_set(error, "invalid e_phentsize: %u",
				    obj->ehdr64->e_phentsize);
				goto err;
			}
		}
		if (obj->ehdr64->e_type == ET_REL)
			break;
		for (i = 0; i < obj->ehdr64->e_phnum; i++) {
			if (obj->phdr64[i].p_type == PT_NOTE) {
				obj->flags |= ELF_NOTE_F;
				obj->note64 = (Elf64_Nhdr *)&obj->mem[obj->phdr64[i].p_offset];
				obj->note_size = obj->phdr64[i].p_filesz;
			} else if (obj->phdr64[i].p_type == PT_DYNAMIC) {
				obj->flags |= ELF_DYNAMIC_F;
				obj->dynamic64 = (Elf64_Dyn *)&obj->mem[obj->phdr64[i].p_offset];
				obj->dynamic_size = obj->phdr64[i].p_filesz;
			} else if (obj->phdr64[i].p_type == PT_GNU_EH_FRAME) {
				obj->eh_frame = &obj->mem[obj->phdr64[i].p_offset];
				obj->eh_frame_size = obj->phdr64[i].p_filesz;
			} else if (obj->phdr64[i].p_type == PT_LOAD && obj->phdr64[i].p_offset == 0) {
				obj->pt_load[obj->load_count].flag |= ELF_PT_LOAD_TEXT_F;
				text_found = true;
				memcpy(&obj->pt_load[obj->load_count++].phdr64, &obj->phdr64[i],
				    sizeof(Elf64_Phdr));
			} else if (obj->phdr64[i].p_type == PT_LOAD && text_found == false) {
				if ((obj->phdr64[i].p_flags & (PF_R|PF_X)) == (PF_R | PF_X)) {
					obj->pt_load[obj->load_count].flag |= ELF_PT_LOAD_TEXT_F;
					text_found = true;
					memcpy(&obj->pt_load[obj->load_count++].phdr64,
					    &obj->phdr64[i], sizeof(Elf64_Phdr));
				}
			} else if (obj->phdr64[i].p_type == PT_LOAD) {
				if (data_found == true) {
					obj->pt_load[obj->load_count].flag |= ELF_PT_LOAD_MISC_F;
					memcpy(&obj->pt_load[obj->load_count++].phdr64,
					    &obj->phdr64[i], sizeof(Elf64_Phdr));
				} else {
					obj->pt_load[obj->load_count].flag |= ELF_PT_LOAD_DATA_F;
					data_found = true;
					memcpy(&obj->pt_load[obj->load_count++].phdr64,
					    &obj->phdr64[i], sizeof(Elf64_Phdr));
				}
			}
		}
		break;
	default:
		elf_error_set(error, "unsupported ELF architecture",
		    strerror(errno));
		goto err;
	}

	/*
	 * Were any of the ELF header anomalies such that we should not be
	 * trying to load the section header table? If so lets NOT fuck ourselves.
	 * Sanity checks are good. So Instead lets load all of the section header
	 * data using state of the art reconstruction techniques that were employed
	 * in my beloved ECFS v1 (If the ELF_LOAD_F_FORENSICS flag is set) otherwise
	 * we just skip section parsing/loading, after which we can sort them but
	 * but not now.
	 */
	if (insane_headers(obj) == true) {
		goto final_load_stages;
	}

	/*
	 * Sort the ELF sections if applies. Otherwise we do this by reconstructing
	 * them later on in the loading process (If MALWARE loading flag is set)
	 */
	if (sort_elf_sections(obj, error) == false) {
		elf_error_set(error, "sort_elf_sections failed");
		goto err;
	}
	/*
	 * Set the remaining elf object pointers to the various data structures in the
	 * ELF file.
	 */
	for (i = 0; i < section_count; i++) {
		const char *sname = (obj->e_class == elfclass32) ?
		    &obj->shstrtab[obj->shdr32[i].sh_name] :
		    &obj->shstrtab[obj->shdr64[i].sh_name];
		uint64_t sh_offset = (obj->e_class == elfclass32) ?
		    obj->shdr32[i].sh_offset : obj->shdr64[i].sh_offset;

		if (strcmp(sname, ".strtab") == 0) {
			obj->strtab = (char *)&mem[sh_offset];
		/*
		 * Setup the symbol table, dynamic symbol table,
		 * and string table pointers.
		 */
		} else if (strcmp(sname, ".symtab") == 0) {
			obj->flags |= ELF_SYMTAB_F;
			switch(obj->e_class) {
			case elfclass32:
				obj->symtab_count = obj->shdr32[i].sh_size /
				    sizeof(Elf32_Sym);
				obj->symtab32 =
				    (Elf32_Sym *)&mem[sh_offset];
				break;
			case elfclass64:
				obj->symtab_count = obj->shdr64[i].sh_size /
				    sizeof(Elf64_Sym);
				obj->symtab64 =
				    (Elf64_Sym *)&mem[sh_offset];
				break;
			}
		} else if (strcmp(sname, ".dynsym") == 0) {
			obj->flags |= ELF_DYNSYM_F;
			switch(obj->e_class) {
			case elfclass32:
				obj->dynsym_count = obj->shdr32[i].sh_size /
				    sizeof(Elf32_Sym);
				obj->dynsym32 =
				    (Elf32_Sym *)&mem[sh_offset];
				break;
			case elfclass64:
				obj->dynsym_count = obj->shdr64[i].sh_size /
				    sizeof(Elf64_Sym);
				obj->dynsym64 =
				    (Elf64_Sym *)&mem[sh_offset];
				break;
			}
		} else if (strcmp(sname, ".dynstr") == 0) {
			obj->dynstr = (char *)&mem[sh_offset];
		} else if (strcmp(sname, ".strtab") == 0) {
			obj->strtab = (char *)&mem[sh_offset];
		} else if (strcmp(sname, ".plt") == 0) {
			obj->flags |= ELF_PLT_F;
		}
	}

final_load_stages:
	if (load_dynamic_segment_data(obj) == false) {
		elf_error_set(error, "failed to build dynamic segment data");
		goto err;
	}
	/*
	 * These next two build_*sym_data() functions will NOT work
	 * if there are no section headers. They will rely on all
	 * sorts of data being available in the section headers so
	 * we must reconstruct the internal section data using the
	 * the state-of-the-art methods used by ECFS.
	 */
	if (insane_headers(obj) == true &&
	    (load_flags & ELF_LOAD_F_FORENSICS)) {
		elf_error_t suberror;

		if (reconstruct_elf_sections(obj, &suberror) == false) {
			elf_error_set(error, "failed to build forensics data: %s",
			    elf_error_msg(&suberror));
			goto err;
		}
	} else {
		/*
		 * If the headers are insane but we are not using the
		 * FORENSICS flag in elf_open_object, then skip the
		 * reconstruction of necessary data.
		 */
		if (insane_headers(obj) == true)
			goto finalize;
	}

	/*
	 * Build a cache for symtab and dynsym as needed.
	 */
	hcreate_r(obj->symtab_count, &obj->cache.symtab);
	hcreate_r(obj->dynsym_count, &obj->cache.dynsym);
	hcreate_r(obj->dynsym_count, &obj->cache.plt);

	if (build_dynsym_data(obj) == false) {
		elf_error_set(error, "failed to build dynamic symbol data");
		goto err;
	}
	if (build_symtab_data(obj) == false) {
		elf_error_set(error, "failed to build symtab symbol data");
		goto err;
	}
	if (obj->flags & ELF_PLT_F) {
		if (build_plt_data(obj) == false) {
			elf_error_set(error, "failed to build plt cache and list");
			goto err;
		}
	}
finalize:
	if (obj->dynsym_count > 0)
		obj->flags |= ELF_DYNSYM_F;
	if (obj->symtab_count > 0)
		obj->flags |= ELF_SYMTAB_F;

	obj->flags |= obj->type == ET_DYN ? ELF_PIE_F : 0;

	return true;
err:
	close(fd);
	munmap(mem, st.st_size);
	return false;
}

void
elf_close_object(elfobj_t *obj)
{
	/*
	 * Free up cache memory, arrays, and linked lists
	 */
	free_lists(obj);
	free_caches(obj);
	free_arrays(obj);
	/*
	 * Unmap memory
	 */
	munmap(obj->mem, obj->size);
}
