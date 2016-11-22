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
#include "../include/libelfmaster.h"

#define ROUNDUP(x, y) ((x + (y - 1)) & ~(y - 1))

#ifdef DEBUG
#define DEBUG_LOG(...) do { fprintf(stderr, __VA_ARGS__); } while(0)
#else
#define DEBUG_LOG(...) do {} while(0)
#endif

#ifdef __GNUC__
#define likely(x)       __builtin_expect(!!(x), 1)
#define unlikely(x)     __builtin_expect(!!(x), 0)
#else
#define likely(x)       (x)
#define unlikely(x)     (x)
#endif

/*
 **** libelfmaster supports ld.so.cache for shared library resolution
*/

#define CACHE_FILE "/etc/ld.so.cache"
#define CACHEMAGIC "ld.so-1.7.0"

struct file_entry {
	int flags;
	uint32_t key;
	uint32_t value;
};

struct cache_file {
	char magic[sizeof CACHEMAGIC - 1];
	uint32_t nlibs;
	struct file_entry libs[0];
};

#define CACHEMAGIC_NEW "glibc-ld.so.cache"
#define CACHE_VERSION "1.1"
#define CACHEMAGIC_VERSION_NEW CACHEMAGIC_NEW CACHE_VERSION

struct file_entry_new {
	int32_t flags;
	uint32_t key;
	uint32_t value;
	uint32_t osversion;
	uint64_t hwcap;
};

struct cache_file_new {
	char magic[sizeof CACHEMAGIC_NEW - 1];
	char version[sizeof CACHE_VERSION - 1];
	uint32_t nlibs;		/* number of entries */
	uint32_t len_strings;	/* size of string table */
	uint32_t unused[5];	/* space for future extension */
	struct file_entry_new libs[0]; /* Entries describing libraries */
	/* After this the string table of size len_strings is found */
};

#define ALIGN_CACHE(addr)				\
	(((addr) + __alignof__ (struct cache_file_new) -1)	\
	    & (~(__alignof__ (struct cache_file_new) - 1)))

static bool
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
	const struct elf_section *s0 = *(void **)p0;
	const struct elf_section *s1 = *(void **)p1;

	return strcmp(s0->name, s1->name);
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

        switch(obj->arch) {
        case i386:
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
        case x64:
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
	switch(obj->arch) {
	case i386:
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
	case x64:
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

	switch(obj->arch) {
	case i386:
		e.shdr32 = (Elf32_Shdr *)shdr;
		if (e.shdr32->sh_offset >= obj->size)
			return NULL;
		return (void *)((uint8_t *)&obj->mem[e.shdr32->sh_offset]);
	case x64:
		e.shdr64 = (Elf64_Shdr *)shdr;
		if (e.shdr64->sh_offset >= obj->size)
			return NULL;
		return (void *)((uint8_t *)&obj->mem[e.shdr64->sh_offset]);
	}
	return NULL;
}

static bool
build_dynsym_data(struct elfobj *obj)
{
	ENTRY e, *ep;
	unsigned int i;
	Elf32_Sym *dsym32;
	Elf64_Sym *dsym64;
	struct elf_dynsym_list *list = &obj->list.dynsym;

	LIST_INIT(&obj->list.symtab);

	for (i = 0; i < obj->dynsym_count; i++) {
		struct elf_symbol_node *symbol = malloc(sizeof(*symbol));

		if (symbol == NULL)
			return false;

		switch(obj->arch) {
		case i386:
			dsym32 = obj->dynsym32;
			symbol->name = &obj->dynstr[dsym32[i].st_name];
			symbol->value = dsym32[i].st_value;
			symbol->shndx = dsym32[i].st_shndx;
			symbol->size = dsym32[i].st_size;
			symbol->bind = ELF32_ST_BIND(dsym32[i].st_info);
			symbol->type = ELF32_ST_TYPE(dsym32[i].st_info);
			symbol->visibility = ELF32_ST_VISIBILITY(dsym32[i].st_other);
			break;
		case x64:
			dsym64 = obj->dynsym64;
			symbol->name = &obj->dynstr[dsym64[i].st_name];
			symbol->value = dsym64[i].st_value;
			symbol->shndx = dsym64[i].st_shndx;
			symbol->size = dsym64[i].st_size;
			symbol->bind = ELF64_ST_BIND(dsym64[i].st_info);
			symbol->type = ELF64_ST_TYPE(dsym64[i].st_info);
			symbol->visibility = ELF64_ST_VISIBILITY(dsym64[i].st_other);
			break;
		}
		e.key = (char *)symbol->name;
		e.data = (void *)symbol;
		hsearch_r(e, ENTER, &ep, &obj->cache.dynsym);
		if (ep == NULL && errno == ENOMEM)
			return false;
		/*
		 * We also maintain a linked list for the iterator
		 */
		LIST_INSERT_HEAD(list, symbol, _linkage);
	}
	return true;
}

static bool
build_symtab_data(struct elfobj *obj)
{
	ENTRY e, *ep;
	unsigned int i;
	Elf32_Sym *symtab32;
	Elf64_Sym *symtab64;
	struct elf_symtab_list *list = &obj->list.symtab;

	LIST_INIT(&obj->list.symtab);

	for (i = 0; i < obj->symtab_count; i++) {
		struct elf_symbol_node *symbol = malloc(sizeof(*symbol));

		if (symbol == NULL)
			return false;

		switch(obj->arch) {
		case i386:
			symtab32 = obj->symtab32;
			symbol->name = &obj->strtab[symtab32[i].st_name];
			symbol->value = symtab32[i].st_value;
			symbol->shndx = symtab32[i].st_shndx;
			symbol->size = symtab32[i].st_size;
			symbol->bind = ELF32_ST_BIND(symtab32[i].st_info);
			symbol->type = ELF32_ST_TYPE(symtab32[i].st_info);
			symbol->visibility = ELF32_ST_VISIBILITY(symtab32[i].st_other);
			break;
		case x64:
			symtab64 = obj->symtab64;
			symbol->name = &obj->strtab[symtab64[i].st_name];
			symbol->value = symtab64[i].st_value;
			symbol->shndx = symtab64[i].st_shndx;
			symbol->size = symtab64[i].st_size;
			symbol->bind = ELF64_ST_BIND(symtab64[i].st_info);
			symbol->type = ELF64_ST_TYPE(symtab64[i].st_info);
			symbol->visibility = ELF64_ST_VISIBILITY(symtab64[i].st_other);
			break;
		}
		e.key = (char *)symbol->name;
		e.data = (char *)symbol;
		hsearch_r(e, ENTER, &ep, &obj->cache.symtab);
		if (ep == NULL && errno == ENOMEM)
			return false;
		/*
		 * We also maintain a linked list for the iterator
		 */
		LIST_INSERT_HEAD(list, symbol, _linkage);
	}
	return true;
}

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

/*
 * Compares libraries by version numbers, and returns 0
 * on equal.
 */
static int
ldso_cache_cmp(const char *p1, const char *p2)
{
	while (*p1) {
		if (isdigit(*p1) && isdigit(*p2)) {
			int v1, v2;

			v1 = strtoul(p1, (char **)&p1, 10);
			v2 = strtoul(p2, (char **)&p2, 10);
			if (v1 != v2)
				return v1 - v2;
		}
		else if (isdigit(*p1) && !isdigit(*p2)) {
			return 1;
		} else if (!isdigit(*p1) && isdigit(*p2)) {
			return -1;
		} else if (*p1 != *p2) {
			return *p1 - *p2;
		} else {
			p1++, p2++;
		}
	}
	return *p1 - *p2;
}

#define ldso_cache_verify_offset(offset) (offset < iter->cache_size)

static inline bool
ldso_cache_check_flags(struct elf_shared_object_iterator *iter,
    uint32_t flags)
{
	if (iter->obj->arch == i386) {
		if (flags == 0x803)
			return true;
	} else if (iter->obj->arch == x64) {
		if (flags == 0x303)
			return true;
	}
	return false;
}

static const char *
ldso_cache_bsearch(struct elf_shared_object_iterator *iter,
    const char *name)
{
	int ret;
	uint64_t value;
	uint32_t middle, flags;
	uint32_t left = 0;
	uint32_t right = (iter->cache_flags & ELF_LDSO_CACHE_NEW) ?
	    iter->cache_new->nlibs - 1 : iter->cache->nlibs - 1;
	const char *best = NULL;

	while (left <= right) {
		uint32_t key;

		middle = (left + right) / 2;
		if (iter->flags & ELF_LDSO_CACHE_NEW) {
			key = iter->cache_new->libs[middle].key;
		} else {
			key = iter->cache->libs[middle].key;
		}

		ret = ldso_cache_cmp(name, iter->cache_data + key);
		if (unlikely(ret == 0)) {
			left = middle;
			while (middle > 0) {
				if (iter->flags & ELF_LDSO_CACHE_NEW) {
					key = iter->cache_new->libs[middle - 1].key;
				} else {
					key = iter->cache->libs[middle - 1].key;
				}
				if (ldso_cache_cmp(name,
				    iter->cache_data + key) != 0)
					break;
				middle--;
			}
			do {
				if (iter->flags & ELF_LDSO_CACHE_NEW) {
					value = iter->cache_new->libs[middle].value;
					flags = iter->cache_new->libs[middle].flags;
				} else {
					value = iter->cache->libs[middle].value;
					flags = iter->cache->libs[middle].flags;
				}
				if (middle > left && (ldso_cache_cmp(name,
				    iter->cache_data + key) != 0))
					break;
				if (ldso_cache_check_flags(iter, flags) &&
				    ldso_cache_verify_offset(value)) {
					if (best == NULL) {
						best = iter->cache_data + value;
						break;
					}
				}
			} while (++middle <= right);
			break;
		}
		if (ret < 0) {
			left = middle + 1;
		} else {
			right = middle - 1;
		}
	}
	return best;
}

bool
elf_shared_object_iterator_init(struct elfobj *obj,
    struct elf_shared_object_iterator *iter, const char *cache_path,
    uint32_t flags, elf_error_t *error)
{
	const char *cache_file = cache_path == NULL ? CACHE_FILE : cache_path;

	if (LIST_EMPTY(&obj->list.shared_objects))
		return false;

	/*
	 * This list is only used for recursive resolution
	 * e.g. ELF_SO_RESOLVE_ALL_F
	 */
	LIST_INIT(&iter->yield_list);

	iter->flags = flags;
	iter->cache_flags = 0;
	iter->index = 0;
	iter->obj = obj;

	if ((flags & ELF_SO_RESOLVE_F) == 0 &&
	    (flags & ELF_SO_RESOLVE_ALL_F) == 0)
		goto finish;
	if (flags & ELF_SO_RESOLVE_ALL_F)
		iter->flags |= ELF_SO_RESOLVE_F;

	iter->fd = open(cache_file, O_RDONLY);
	if (iter->fd < 0) {
		return elf_error_set(error, "open %s: %s\n", CACHE_FILE,
		    strerror(errno));
	}
	if (fstat(iter->fd, &iter->st) < 0) {
		return elf_error_set(error, "fstat %s: %s\n", CACHE_FILE,
		    strerror(errno));
	}
	iter->mem = mmap(NULL, iter->st.st_size, PROT_READ, MAP_PRIVATE,
	    iter->fd, 0);
	if (iter->mem == MAP_FAILED) {
		return elf_error_set(error, "mmap %s: %s\n", CACHE_FILE,
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

static bool
ldso_insert_yield_entry(struct elf_shared_object_iterator *iter,
    const char *path)
{
	struct elf_shared_object *so = malloc(sizeof(*so));

	if (so == NULL)
		return false;

	so->path = path;
	so->basename = strrchr(path, '/') + 1;
	LIST_INSERT_HEAD(&iter->yield_list, so, _linkage);
	
}

bool
ldso_recursive_cache_resolve(struct elf_shared_object_iterator *iter,
    const char *bname, elf_error_t *error)
{
	char *path = ldso_cache_bsearch(iter, bname);
	struct elf_shared_object_node *current;
	struct elf_shared_object *so;
	elfobj_t *obj;

	if (path == NULL)
		return false;

	obj = load_elf_object(path, &obj, false, error);
	if (obj == NULL) {
		return elf_error_set(error,
		    "failed to load object: %s\n", path);
	}
	if (LIST_EMPTY(&obj->list.shared_objects))
		return false;
	LIST_FOREACH(current, &obj->list.shared_objects, _linkage) {
		if (current->basename 
}
	
elf_iterator_res_t
elf_shared_object_iterator_next(struct elf_shared_object_iterator *iter,
    struct elf_shared_object *entry, elf_error_t *error)
{

	if (iter->current == NULL)
		return ELF_ITER_DONE;
	/*
	 * Now perform binary search on cache
	 */
	if ((iter->flags & ELF_SO_RESOLVE_F) == 0)
		goto next_basename;

	entry->path = (char *)ldso_cache_bsearch(iter, iter->current->basename);
	if (entry->path == NULL && (iter->flags & ELF_SO_RESOLVE_F)) {
		elf_error_set(error, "ldso_cache_bsearch(%p, %s) failed",
		    iter, iter->current->basename);
		return ELF_ITER_ERROR;
	}
	/*
	 * We will add the path to the internal linked list, which initially
	 * only contains the basenames from DT_NEEDED. In the future when this
	 * iterator is used, it will not call ldso_cache_bsearch again, instead
	 * it will already have the paths cached in the linked list along with
	 * the basenames.
	 */
	iter->current->path = strdup(entry->path);
	if (iter->current_path == NULL) {
		elf_error_set(error, "strdup: %s", strerror(errno));
		return ELF_ITER_ERROR;
	}
	
next_basename:
	entry->basename = iter->current->basename;
	iter->current = LIST_NEXT(iter->current, _linkage);
	return ELF_ITER_OK;
}

bool
elf_relocation_iterator_init(struct elfobj *obj,
    struct elf_relocation_iterator *iter)
{
	unsigned int i;

	iter->obj = obj;
	iter->index = 0;

	LIST_INIT(&iter->list);
	if (obj->arch == i386) {
		Elf32_Ehdr *ehdr32 = obj->ehdr32;
		Elf32_Shdr *shdr32 = obj->shdr32;

		/*
		 * We build a linked list which contains the relocation sections
		 * that we must parse.
		 */
		for (i = 0; i <	ehdr32->e_shnum; i++) {
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
	} else if (obj->arch == x64) {
		Elf64_Ehdr *ehdr64 = obj->ehdr64;
		Elf64_Shdr *shdr64 = obj->shdr64;

		for (i = 0; i < ehdr64->e_shnum; i++) {
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
	iter->current = LIST_FIRST(&iter->list);
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

	if (current == NULL)
		return ELF_ITER_DONE;

	/*
	 * If we're dealing sections rela.plt, rel.plt
	 * rela.dyn or rel.dyn, then we need to look up
	 * symbol indexes in the dynamic symbol table.
	 */
	if (strstr(current->section_name, ".plt") ||
	    strstr(current->section_name, ".dyn")) {
		which = SHT_DYNSYM;
	} else {
		which = SHT_SYMTAB;
	}

	if (iter->obj->arch == i386) {
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
				return false;
			
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
				return false;

			entry->offset = current->rel32[i].r_offset;
			entry->type = ELF32_R_TYPE(current->rel32[i].r_info);
			entry->addend = 0;
			entry->symname = (char *)symbol.name;
			entry->shdrname = current->section_name;
			return ELF_ITER_OK;
		}
	} else if (iter->obj->arch == x64) {
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
				return false;
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
				return false;
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

	switch(iter->obj->arch) {
	case i386:
		if (iter->obj->dynamic32 == NULL)
			return ELF_ITER_DONE;
		if (iter->obj->dynamic32[i].d_tag == DT_NULL)
			return ELF_ITER_DONE;
		entry->tag = iter->obj->dynamic32[i].d_tag;
		entry->value = iter->obj->dynamic32[i].d_un.d_val;
		break;
	case x64:
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
	switch(iter->obj->arch) {
	case i386:
		iter->note32 = iter->obj->note32;
		break;
	case x64:
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

	switch(iter->obj->arch) {
	case i386:
		if (iter->note32 == NULL)
			return ELF_ITER_DONE;
		entry->mem = ELFNOTE_DESC(iter->note32);
		entry->size = iter->note32->n_descsz;
		entry->type = iter->note32->n_type;
		entry_len = ELFNOTE_ALIGN(iter->note32->n_descsz +
		    iter->note32->n_namesz + sizeof(long));
		iter->note32 = ELFNOTE32_NEXT(iter->note32);
		break;
	case x64:
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

	switch(obj->arch) {
	case i386:
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
	case x64:
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

#if 0
void
elf_pltgot_iterator_init(struct elfobj *obj, struct elf_pltgot_iterator *iter)
{

	iter->index = 0;
	iter->obj = 0;
}
#endif
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

	switch(obj->arch) {
	case i386:
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
	case x64:
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
 * Used internally to build information from the dynamic segment.
 */
static bool
load_dynamic_segment_data(struct elfobj *obj)
{
	struct elf_dynamic_entry entry;
	elf_dynamic_iterator_t iter;
	elf_iterator_res_t res;
	struct elf_shared_object_node *so;

	LIST_INIT(&obj->list.shared_objects);
	elf_dynamic_iterator_init(obj, &iter);
	for (;;) {
		res = elf_dynamic_iterator_next(&iter, &entry);
		if (res == ELF_ITER_DONE)
			return true;
		if (res == ELF_ITER_ERROR)
			return false;
		switch(entry.tag) {
		case DT_PLTGOT:
			obj->dynseg.pltgot.addr = entry.value;
			break;
		case DT_PLTRELSZ:
			obj->dynseg.pltrel.size = entry.value;
			break;
		case DT_SYMTAB:
			obj->dynseg.dynsym.addr = entry.value;
			break;
		case DT_STRTAB:
			obj->dynseg.dynstr.addr = entry.value;
			break;
		case DT_PLTREL:
			obj->dynseg.pltrel.type = entry.value;
			break;
		case DT_JMPREL:
			obj->dynseg.pltrel.addr = entry.value;
			break;
		case DT_INIT:
			obj->dynseg.init.addr = entry.value;
			break;
		case DT_FINI:
			obj->dynseg.fini.addr = entry.value;
			break;
		case DT_NEEDED:
			so = malloc(sizeof(*so));
			if (so == NULL)
				return false;
			so->basename = elf_dynamic_string(obj, entry.value);
			LIST_INSERT_HEAD(&obj->list.shared_objects, so,
			    _linkage);
			break;
		default:
			break;
		}
	}
	return true;
}

/*
 * Secure ELF loader.
 */
bool
load_elf_object(const char *path, struct elfobj *obj, bool modify,
    elf_error_t *error)
{
	int fd;
	uint32_t i;
	unsigned int open_flags = O_RDONLY;
	unsigned int mmap_perms = PROT_READ;
	unsigned int mmap_flags = MAP_PRIVATE;
	uint8_t *mem;
	uint16_t e_machine;
	struct stat st;
	size_t section_count;

	/*
	 * We count on this being initialized for various sanity checks.
	 */
	memset(obj, 0, sizeof(*obj));

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
	obj->mem = mem;

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
		obj->entry_point = obj->ehdr32->e_entry;
		obj->type = obj->ehdr32->e_type;
		obj->segment_count = obj->ehdr32->e_phnum;
		obj->flags |= (obj->ehdr32->e_shnum > 0 ? ELF_SHDRS_F : 0);
		if (obj->ehdr32->e_shstrndx > obj->size) {
			elf_error_set(error, "invalid e_shstrndx: %u\n",
			    obj->ehdr32->e_shstrndx);
			goto err;
		}
		obj->shstrtab =
		    (char *)&mem[obj->shdr32[obj->ehdr32->e_shstrndx].sh_offset];
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
		for (i = 0; i < obj->ehdr32->e_phnum; i++) {
			if (obj->phdr32[i].p_type == PT_NOTE) {
				obj->note32 = (Elf32_Nhdr *)&obj->mem[obj->phdr32[i].p_offset];
				obj->note_size = obj->phdr32[i].p_filesz;
			} else if (obj->phdr32[i].p_type == PT_DYNAMIC) {
				obj->dynamic32 = (Elf32_Dyn *)&obj->mem[obj->phdr32[i].p_offset];
				obj->dynamic_size = obj->phdr32[i].p_filesz;
			} else if (obj->phdr32[i].p_type == PT_GNU_EH_FRAME) {
				obj->eh_frame = &obj->mem[obj->phdr32[i].p_offset];
				obj->eh_frame_size = obj->phdr32[i].p_filesz;
			}
		}
		break;
	case EM_X86_64:
		obj->arch = x64;
		obj->ehdr64 = (Elf64_Ehdr *)mem;
		obj->phdr64 = (Elf64_Phdr *)&mem[obj->ehdr64->e_phoff];
		obj->shdr64 = (Elf64_Shdr *)&mem[obj->ehdr64->e_shoff];
		obj->entry_point = obj->ehdr64->e_entry;
		obj->type = obj->ehdr64->e_type;
		obj->segment_count = obj->ehdr64->e_phnum;
		obj->flags |= (obj->ehdr64->e_shnum > 0 ? ELF_SHDRS_F : 0);
		if (obj->ehdr64->e_shstrndx > obj->size) {
			elf_error_set(error, "invalid e_shstrndx: %lu",
			    obj->ehdr64->e_shstrndx);
			goto err;
		}
		obj->shstrtab =
		    (char *)&mem[obj->shdr64[obj->ehdr64->e_shstrndx].sh_offset];
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
		for (i = 0; i < obj->ehdr64->e_phnum; i++) {
			if (obj->phdr64[i].p_type == PT_NOTE) {
				obj->note64 = (Elf64_Nhdr *)&obj->mem[obj->phdr64[i].p_offset];
				obj->note_size = obj->phdr64[i].p_filesz;
			} else if (obj->phdr64[i].p_type == PT_DYNAMIC) {
				obj->dynamic64 = (Elf64_Dyn *)&obj->mem[obj->phdr64[i].p_offset];
				obj->dynamic_size = obj->phdr64[i].p_filesz;
			} else if (obj->phdr64[i].p_type == PT_GNU_EH_FRAME) {
				obj->eh_frame = &obj->mem[obj->phdr64[i].p_offset];
				obj->eh_frame_size = obj->phdr64[i].p_filesz;
			}
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
	    malloc(sizeof(struct elf_section *) * (section_count + 1));
	if (obj->sections == NULL) {
		elf_error_set(error, "malloc: %s", strerror(errno));
		goto err;
	}
	for (i = 0; i < section_count; i++) {
		obj->sections[i] = malloc(sizeof(struct elf_section));
		if (obj->sections[i] == NULL) {
			elf_error_set(error, "malloc: %s", strerror(errno));
			goto err;
		}
		switch(obj->arch) {
		case i386:
			obj->sections[i]->name =
			    strdup(&obj->shstrtab[obj->shdr32[i].sh_name]);
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
			    strdup(&obj->shstrtab[obj->shdr64[i].sh_name]);
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

	/*
	 * Sorting an array of pointers to struct elf_section
	 */
	qsort(obj->sections, section_count,
	    sizeof(struct elf_section *), section_name_cmp);

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
				obj->symtab_count = obj->shdr32[i].sh_size /
				    sizeof(Elf32_Sym);
				obj->symtab32 =
				    (Elf32_Sym *)&mem[sh_offset];
				break;
			case x64:
				obj->symtab_count = obj->shdr64[i].sh_size /
				    sizeof(Elf64_Sym);
				obj->symtab64 =
				    (Elf64_Sym *)&mem[sh_offset];
				break;
			}
		} else if (strcmp(sname, ".dynsym") == 0) {
			switch(obj->arch) {
			case i386:
				obj->dynsym_count = obj->shdr32[i].sh_size /
				    sizeof(Elf32_Sym);
				obj->dynsym32 =
				    (Elf32_Sym *)&mem[sh_offset];
				break;
			case x64:
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
		}
	}
	if (load_dynamic_segment_data(obj) == false) {
		elf_error_set(error, "failed to build dynamic segment data");
		goto err;
	}
	/*
	 * Build a cache for symtab and dynsym as needed.
	 */
	hcreate_r(obj->symtab_count, &obj->cache.symtab);
	hcreate_r(obj->dynsym_count, &obj->cache.dynsym);
	if (build_dynsym_data(obj) == false) {
		elf_error_set(error, "failed to build dynamic symbol data");
		goto err;
	}
	if (build_symtab_data(obj) == false) {
		elf_error_set(error, "failed to build symtab symbol data");
		goto err;
	}
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
