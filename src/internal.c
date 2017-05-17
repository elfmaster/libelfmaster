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
#include "internal.h"
#include "misc.h"


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

/*
 * TODO, switch to using qsort_r, and add two separate sorted arrays
 * of pointers to section structs. One which is sorted by address, and
 * one sorted by name.
 */
int
section_name_cmp(const void *p0, const void *p1)
{
	const struct elf_section *s0 = *(void **)p0;
	const struct elf_section *s1 = *(void **)p1;

	return strcmp(s0->name, s1->name);
}

/*
 * Same for x86 and i386
 */
#define ELF_RELOC_JUMP_SLOT 7

bool
build_plt_data(struct elfobj *obj)
{
	ENTRY e, *ep;
	struct elf_section plt;
	struct elf_relocation_iterator r_iter;
	struct elf_relocation r_entry;
	struct elf_plt_node *plt_node;
	uint64_t plt_addr;
	elf_iterator_res_t res;

	if (elf_section_by_name(obj, ".plt", &plt) == false)
		return false;
	/*
	 * We can use the relocation iterator at this point, since all of its
	 * necessary components have been set already within elfobj *
	 */
	if (elf_relocation_iterator_init(obj, &r_iter) == false)
		return false;

	plt_node = malloc(sizeof(*plt_node));
	if (plt_node == NULL)
		return false;

	/*
	 * First PLT entry is always PLT-0, even though objdump always
	 * names it with same symbol name as the next entry.
	 */
	plt_node->addr = plt.address;
	plt_node->symname = (char *)"PLT-0";
	LIST_INSERT_HEAD(&obj->list.plt, plt_node, _linkage);

	/*
	 * Also hash the PLT entries by symbol name.
	 */
	e.key = (char *)plt_node->symname;
	e.data = (void *)plt_node;
	hsearch_r(e, ENTER, &ep, &obj->cache.plt);
	plt_addr = plt.address + plt.entsize;

	for (;;) {
		res = elf_relocation_iterator_next(&r_iter, &r_entry);
		if (res == ELF_ITER_ERROR)
			return false;
		if (res == ELF_ITER_DONE)
			break;
		if (r_entry.type != ELF_RELOC_JUMP_SLOT)
			continue;
		plt_node = malloc(sizeof(*plt_node));
		if (plt_node == NULL)
			return false;
		plt_node->addr = plt_addr;
		plt_node->symname = r_entry.symname;
		LIST_INSERT_HEAD(&obj->list.plt, plt_node, _linkage);
		e.key = (char *)plt_node->symname;
		e.data = (void *)plt_node;
		hsearch_r(e, ENTER, &ep, &obj->cache.plt);
		plt_addr += plt.entsize;
	}
	return true;
}

bool
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

		switch(obj->e_class) {
		case elfclass32:
			dsym32 = obj->dynsym32;
			symbol->name = &obj->dynstr[dsym32[i].st_name];
			symbol->value = dsym32[i].st_value;
			symbol->shndx = dsym32[i].st_shndx;
			symbol->size = dsym32[i].st_size;
			symbol->bind = ELF32_ST_BIND(dsym32[i].st_info);
			symbol->type = ELF32_ST_TYPE(dsym32[i].st_info);
			symbol->visibility = ELF32_ST_VISIBILITY(dsym32[i].st_other);
			break;
		case elfclass64:
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

bool
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

		switch(obj->e_class) {
		case elfclass32:
			symtab32 = obj->symtab32;
			symbol->name = &obj->strtab[symtab32[i].st_name];
			symbol->value = symtab32[i].st_value;
			symbol->shndx = symtab32[i].st_shndx;
			symbol->size = symtab32[i].st_size;
			symbol->bind = ELF32_ST_BIND(symtab32[i].st_info);
			symbol->type = ELF32_ST_TYPE(symtab32[i].st_info);
			symbol->visibility = ELF32_ST_VISIBILITY(symtab32[i].st_other);
			break;
		case elfclass64:
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

/*
 * Compares libraries by version numbers, and returns 0
 * on equal.
 */
int
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
		if (iter->cache_flags & ELF_LDSO_CACHE_NEW) {
			key = iter->cache_new->libs[middle].key;
		} else {
			key = iter->cache->libs[middle].key;
		}
		ret = ldso_cache_cmp(name, iter->cache_data + key);
		if (unlikely(ret == 0)) {
			left = middle;
			while (middle > 0) {
				if (iter->cache_flags & ELF_LDSO_CACHE_NEW) {
					key = iter->cache_new->libs[middle - 1].key;
				} else {
					key = iter->cache->libs[middle - 1].key;
				}
				if (ldso_cache_cmp(name,
				    iter->cache_data + key) != 0) {
					break;
				}
				--middle;
			}
			do {
				uint32_t new_key;

				if (iter->cache_flags & ELF_LDSO_CACHE_NEW) {
					new_key = iter->cache_new->libs[middle].key;
					value = iter->cache_new->libs[middle].value;
					flags = iter->cache_new->libs[middle].flags;
				} else {
					new_key = iter->cache->libs[middle].key;
					value = iter->cache->libs[middle].value;
					flags = iter->cache->libs[middle].flags;
				}
				if (middle > left && (ldso_cache_cmp(name,
				    iter->cache_data + new_key) != 0))
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

/*
 * We add shared objects to the yield list. Since there will be duplicates we
 * also maintain a hash table of entries so we know which ones we already have
 * in the list, without having to traverse the list.
 */
static bool
ldso_insert_yield_entry(struct elf_shared_object_iterator *iter,
    const char *path)
{
	struct elf_shared_object_node *so = malloc(sizeof(*so));
	ENTRY e = {.key = (char *)path, (char *)path}, *ep;

	if (so == NULL)
		return false;
	/*
	 * If we find the item in the cache then don't add it
	 * to the list again.
	 */
	if (hsearch_r(e, FIND, &ep, &iter->yield_cache) != 0) {
		free(so);
		return true;
	}
	/*
	 * Add path to cache.
	 */
	if (hsearch_r(e, ENTER, &ep, &iter->yield_cache) == 0)
		return false;
	/*
	 * Add path to yield list.
	 */
	so->path = (char *)path;
	so->basename = strrchr(path, '/') + 1;
	LIST_INSERT_HEAD(&iter->yield_list, so, _linkage);
	iter->yield = LIST_FIRST(&iter->yield_list);
	return true;
}

bool
ldso_recursive_cache_resolve(struct elf_shared_object_iterator *iter,
    const char *bname)
{
	const char *path = ldso_cache_bsearch(iter, bname);
	struct elf_shared_object_node *current;
	elfobj_t obj;
	elf_error_t error;

	if (path == NULL)
		return false;

	if (elf_open_object(path, &obj, false, &error) == false)
		return false;

	if (LIST_EMPTY(&obj.list.shared_objects))
		goto done;

	LIST_FOREACH(current, &obj.list.shared_objects, _linkage) {

		if (current->basename == NULL)
			goto err;

		path = (char *)ldso_cache_bsearch(iter, current->basename);
		if (path == NULL) {
			DEBUG_LOG("cannot resolve %s\n", current->basename);
			goto err;
		}
		/*
		 * We update the existing object list to now contain the
		 * full path. That way any subsequent calls to the shared
		 * object iterator will use the linked list cache.
		 */
		current->path = strdup(path);
		if (current->path == NULL)
			goto err;
		if (ldso_insert_yield_entry(iter, current->path) == false)
			goto err;
		if (ldso_recursive_cache_resolve(iter, current->basename) == false)
			goto err;
	}
done:
	elf_close_object(&obj);
	return true;
err:
	elf_close_object(&obj);
	return false;
}

/*
 * Used internally to build information from the dynamic segment.
 */
bool
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
		case DT_STRSZ:
			obj->dynseg.dynstr.size = entry.value;
			break;
		case DT_HASH:
			obj->dynseg.hash.addr = entry.value;
			break;
		case DT_PLTREL:
			obj->flags |= ELF_PLT_RELOCS_F;
			obj->dynseg.pltrel.type = entry.value;
			break;
		case DT_JMPREL:
			obj->dynseg.pltrel.addr = entry.value;
			break;
		case DT_RELA:
			obj->dynseg.rela.addr = entry.value;
			break;
		case DT_RELASZ:
			obj->dynseg.rela.size = entry.value;
			break;
		case DT_REL:
			obj->dynseg.rel.addr = entry.value;
			break;
		case DT_RELSZ:
			obj->dynseg.rel.size = entry.value;
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

void
free_lists(elfobj_t *obj)
{
	if (LIST_EMPTY(&obj->list.symtab) == 0) {
		struct elf_symbol_node *current, *next;

		LIST_FOREACH_SAFE(current, &obj->list.symtab,
		    _linkage, next) {
			free(current);
		}
	}
	if (LIST_EMPTY(&obj->list.dynsym) == 0) {
		struct elf_symbol_node *current, *next;

		LIST_FOREACH_SAFE(current, &obj->list.dynsym,
		    _linkage, next) {
			free(current);
		}
	}
	if (LIST_EMPTY(&obj->list.plt) == 0) {
		struct elf_plt_node *current, *next;

		LIST_FOREACH_SAFE(current, &obj->list.plt,
		    _linkage, next) {
			free(current);
		}
	}
	if (LIST_EMPTY(&obj->list.shared_objects) == 0) {
		struct elf_shared_object_node *current, *next;

		LIST_FOREACH_SAFE(current, &obj->list.shared_objects,
		    _linkage, next) {
			free(current);
		}
	}
	return;
}

void
free_caches(elfobj_t *obj)
{

	hdestroy_r(&obj->cache.symtab);
	hdestroy_r(&obj->cache.dynsym);
	hdestroy_r(&obj->cache.plt);
	return;
}

void
free_arrays(elfobj_t *obj)
{
	size_t i;

	for (i = 0; i < obj->section_count; i++) {
		free(obj->sections[i]->name);
		free(obj->sections[i]);
	}
	free(obj->sections);
	return;
}
