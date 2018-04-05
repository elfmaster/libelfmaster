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


/*
 * TODO Why is this defined in internal.c?
 */
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

const char *
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
e* ldso_malloc allows us to maintain a linked list of heap
 * allocations used for the shared object path names, this way
 * we can keep them available in the cache throughout the duration
 * of the entire iterator, rather than free them once we yield
 * them. This is necessary in order to make sure we don't yield
 * duplicates.
 */
static void *
ldso_malloc(struct elf_shared_object_iterator *iter, size_t size)
{
	void *p;
	struct elf_malloc_node *n;

	p = malloc(size);
	if (p == NULL)
		return NULL;
	n = malloc(sizeof(*n));
	if (n == NULL)
		return NULL;
	n->ptr = p;
	LIST_INSERT_HEAD(&iter->malloc_list, n, _linkage);
	return n->ptr;
}

static char *
ldso_strdup(struct elf_shared_object_iterator *iter, const char *s)
{

	char *string;

	string = ldso_malloc(iter, strlen(s) + 1);
	if (string == NULL)
		return NULL;
	strcpy(string, s);
	return string;
}

void
ldso_free_malloc_list(struct elf_shared_object_iterator *iter)
{
	struct elf_malloc_node *next, *current;

	LIST_FOREACH_SAFE(current, &iter->malloc_list, _linkage, next) {
		free(current->ptr);
		free(current);
	}
	return;
}

void
ldso_cleanup(struct elf_shared_object_iterator *iter)
{

	ldso_free_malloc_list(iter);
	if (iter->flags & ELF_SO_RESOLVE_ALL_F)
		hdestroy_r(&iter->yield_cache);
	(void) munmap(iter->mem, iter->st.st_size);
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
	ENTRY e = {(char *)path, (char *)path}, *ep;

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

/*
 * Inserts path into yield cache, but not into the yield list.
 * this is necessary when the iterator yields top-level paths
 * to make sure they don't end up in the yield list and therefore
 * get yielded to the user as a duplicate.
 */
bool
ldso_insert_yield_cache(struct elf_shared_object_iterator *iter,
    const char *path)
{
	ENTRY e = {(char *)path, (char *)path}, *ep;

	if (hsearch_r(e, FIND, &ep, &iter->yield_cache) != 0)
		return true;
	if (hsearch_r(e, ENTER, &ep, &iter->yield_cache) == 0)
		return false;
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

	if (path == NULL) {
		return true;
	}
	if (elf_open_object(path, &obj, false, &error) == false) {
		return false;
	}
	if (LIST_EMPTY(&obj.list.shared_objects))
		goto done;

	LIST_FOREACH(current, &obj.list.shared_objects, _linkage) {
		if (current->basename == NULL) {
			goto err;
		}
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
		current->path = ldso_strdup(iter, path);
		if (current->path == NULL) {
			goto err;
		}
		if (ldso_insert_yield_entry(iter, current->path) == false){
			goto err;
		}
		if (ldso_recursive_cache_resolve(iter, current->basename) == false){
			goto err;
		}
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
	uint32_t dt_pltgot = 0, dt_pltrelsz = 0, dt_symtab = 0,
	    dt_strtab = 0, dt_strsz = 0, dt_hash = 0, dt_pltrel = 0,
	    dt_jmprel = 0, dt_rela = 0, dt_relasz = 0, dt_rel = 0, dt_relsz = 0,
	    dt_fini = 0, dt_init = 0;

	LIST_INIT(&obj->list.shared_objects);
	elf_dynamic_iterator_init(obj, &iter);
	for (;;) {
		res = elf_dynamic_iterator_next(&iter, &entry);
		if (res == ELF_ITER_DONE)
			return true;
		if (res == ELF_ITER_ERROR)
			return false;
		obj->dynseg.exists = true;
		/*
		 * SECURITY: Some of these tags are expected more
		 * than once
		 * like DT_NEEDED. But an attacker who wants to
		 * circumvent our reconstruction could put two
		 * DT_PLTGOT tags for instance and we would save
		 * the second one as the PLT/GOT address, and it
		 * could be bunk. So lets make sure there's only
		 * one of each unless it expected otherwise.
		 * Eventually lets make sure to do further validation
		 * i.e. does the pltgot.addr even point to a valid
		 * location? (i.e. is it in the data segment)
		 */
		switch(entry.tag) {
		case DT_PLTGOT:
			if (dt_pltgot++ > 0)
				break;
			obj->dynseg.pltgot.addr = entry.value;
			break;
		case DT_PLTRELSZ:
			if (dt_pltrelsz++ > 0)
				break;
			obj->dynseg.pltrel.size = entry.value;
			break;
		case DT_SYMTAB:
			if (dt_symtab++ > 0)
				break;
			obj->dynseg.dynsym.addr = entry.value;
			break;
		case DT_STRTAB:
			if (dt_strtab++ > 0)
				break;
			obj->dynseg.dynstr.addr = entry.value;
			break;
		case DT_STRSZ:
			if (dt_strsz++ > 0)
				break;
			obj->dynseg.dynstr.size = entry.value;
			break;
		case DT_HASH:
			if (dt_hash++ > 0)
				break;
			obj->dynseg.hash.addr = entry.value;
			break;
		case DT_PLTREL:
			if (dt_pltrel++ > 0)
				break;
			obj->flags |= ELF_PLT_RELOCS_F;
			obj->dynseg.pltrel.type = entry.value;
			break;
		case DT_JMPREL:
			if (dt_jmprel++ > 0)
				break;
			obj->dynseg.pltrel.addr = entry.value;
			break;
		case DT_RELA:
			if (dt_rela++ > 0)
				break;
			obj->dynseg.rela.addr = entry.value;
			break;
		case DT_RELASZ:
			if (dt_relasz++ > 0)
				break;
			obj->dynseg.rela.size = entry.value;
			break;
		case DT_REL:
			if (dt_rel++ > 0)
				break;
			obj->dynseg.rel.addr = entry.value;
			break;
		case DT_RELSZ:
			if (dt_relsz++ > 0)
				break;
			obj->dynseg.rel.size = entry.value;
			break;
		case DT_INIT:
			if (dt_init++ > 0)
				break;
			obj->dynseg.init.addr = entry.value;
			break;
		case DT_FINI:
			if (dt_fini++ > 0)
				break;
			obj->dynseg.fini.addr = entry.value;
			break;
		case DT_NEEDED:
			/*
			 * We expect multiple NEEDED tags.
			 */
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

bool
insane_headers(elfobj_t *obj)
{

	return (obj->anomalies > 0);
}

/*
 * Returns string table offset, which can then be
 * set into sh_name for the given shdr entry.
 */
static bool
add_shstrtab_entry(elfobj_t *obj, const char *name, uint32_t *out)
{

	if (obj->strindex + strlen(name) + 1 >= obj->internal_shstrtab_size) {
		obj->shstrtab =
		    realloc(obj->shstrtab, obj->internal_shstrtab_size <<= 1);
		if (obj->shstrtab == NULL)
			return false;
	}
	strcpy(&obj->shstrtab[obj->strindex], name);
	*out = (uint32_t)obj->strindex;
	obj->strindex += strlen(name) + 1;
	return true;
}

static void
add_section_entry(elfobj_t *obj, void *ptr)
{

	if (obj->e_class == elfclass32) {
		obj->ehdr32->e_shnum++;
		memcpy(&obj->shdr32[obj->shdrindex++],
		    ptr, sizeof(Elf32_Shdr));
	} else {
		obj->ehdr64->e_shnum++;
		memcpy(&obj->shdr64[obj->shdrindex++],
		    ptr, sizeof(Elf64_Shdr));
	}
	obj->section_count++;
	return;
}
/*
 * This reconstructs the section header tables internally if the
 * FORENSICS flag is passed to elf_object_open(), which is very
 * useful with malware that has corrupted or stripped section
 * headers. The result is that we use techniques such as the
 * dynamic symbol table, and the PT_GNU_EH_FRAME segment to
 * reconstruct symbol and function data which is indespensible
 * for forensics analysts.
 */
bool
reconstruct_elf_sections(elfobj_t *obj, elf_error_t *e)
{
	union {
		Elf32_Shdr shdr32;
		Elf64_Shdr shdr64;
	} elf;
	uint32_t soffset; /* string table offset */
	size_t dynsym_size; /* necessary for calculating various other sizes */
	size_t dynsym_count;

	obj->internal_section_count = INTERNAL_SECTION_COUNT;
	obj->internal_shstrtab_size = INTERNAL_SHSTRTAB_SIZE;
	/*
	 * We only reconstruct ELF sections if the section headers
	 * are damaged or don't exist so we must create our own
	 * string table. Keep in mind we don't update the binary
	 * with section headers, these are for internal representation
	 * only.
	 */
	obj->strindex = 0; /* Should be initialized already anyway */
	obj->shstrtab = malloc(obj->internal_shstrtab_size);
	if (obj->shstrtab == NULL) {
		return elf_error_set(e, "malloc failed");
	}
	/*
	 * Lets reconstruct the dynamic segment
	 * into forensics relevant data in this first
	 * big block of code. Next we will reconstruct
	 * some other areas that don't have to do with the
	 * data segment.
	 */
	switch(obj->e_class) {
	case elfclass32:
		obj->ehdr32->e_shnum = 0; /* initialize incase it was corrupted */
		if (obj->dynseg.exists == false)
			break;
		obj->shdr32 =
		    malloc(sizeof(Elf32_Shdr) * obj->internal_section_count);
		if (obj->shdr32 == NULL)
			return elf_error_set(e, "malloc");
		/*
		 * Create internal representation of .dynsym section
		 */
		if (add_shstrtab_entry(obj, ".dynsym", &soffset) == false) {
			return elf_error_set(e, "add_shstrtab_entry failed");
		}
		elf.shdr32.sh_addr = obj->dynseg.dynsym.addr;
		dynsym_size = elf.shdr32.sh_size =
		    obj->dynseg.dynstr.addr - obj->dynseg.dynsym.addr;
		elf.shdr32.sh_link = 1;
		elf.shdr32.sh_offset =
		    obj->dynseg.dynsym.addr - elf_text_base(obj);
		elf.shdr32.sh_addralign = sizeof(long);
		elf.shdr32.sh_info = 0;
		elf.shdr32.sh_flags = SHF_ALLOC;
		elf.shdr32.sh_name = soffset;
		elf.shdr32.sh_entsize = sizeof(Elf32_Sym);
		add_section_entry(obj, &elf.shdr32);

		/*
		 * .dynstr
		 */
		if (add_shstrtab_entry(obj, ".dynstr", &soffset) == false) {
			return elf_error_set(e, "add_shstrtab_entry failed");
		}
		elf.shdr32.sh_addr = obj->dynseg.dynstr.addr;
		elf.shdr32.sh_size = obj->dynseg.dynstr.size;
		elf.shdr32.sh_link = 0;
		elf.shdr32.sh_offset =
		    obj->dynseg.dynstr.addr - elf_text_base(obj);
		elf.shdr32.sh_addralign = 1;
		elf.shdr32.sh_info = 0;
		elf.shdr32.sh_flags = SHF_ALLOC;
		elf.shdr32.sh_name = soffset;
		elf.shdr32.sh_entsize = 1;
		add_section_entry(obj, &elf.shdr32);
		/*
		 * NOTE: set the ELF_DYNSYM_F flag so the client code knows
		 * if its able to use the dynamic symbol table.
		 */
		obj->flags |= ELF_DYNSYM_F;

		/*
		 * .got.plt
		 */
		if (add_shstrtab_entry(obj, ".got.plt", &soffset) == false) {
			return elf_error_set(e, "add_shstrtab_entry failed");
		}
		elf.shdr32.sh_addr = obj->dynseg.pltgot.addr;
		/*
		 * GOT should be big enough for 3 reserved entries and
		 * then enough slots for each dynamic symbol.
		 */
		dynsym_count = dynsym_size / sizeof(Elf32_Sym);
		elf.shdr32.sh_size = (sizeof(uintptr_t) * 3) +
		    (sizeof(uintptr_t) * dynsym_count);
		elf.shdr32.sh_link = 0;
		elf.shdr32.sh_offset =
		    obj->dynseg.pltgot.addr - elf_text_base(obj);
		elf.shdr32.sh_addralign = sizeof(uintptr_t);
		elf.shdr32.sh_info = 0;
		elf.shdr32.sh_flags = SHF_ALLOC|SHF_WRITE;
		elf.shdr32.sh_name = soffset;
		elf.shdr32.sh_entsize = sizeof(uintptr_t);
		add_section_entry(obj, &elf.shdr32);
		obj->flags |= ELF_PLTGOT_F;

		break;
	case elfclass64:
		obj->ehdr64->e_shnum = 0;
		if (obj->dynseg.exists == false)
			break;
		/*
		 * Create internal representation of .dynsym section
		 */
		obj->shdr64 =
		    malloc(sizeof(Elf64_Shdr) * obj->internal_section_count);
		if (obj->shdr64 == NULL)
			return elf_error_set(e, "malloc");

		if (add_shstrtab_entry(obj, ".dynsym", &soffset) == false) {
			return elf_error_set(e, "add_shstrtab_entry failed");
		}
		elf.shdr64.sh_addr = obj->dynseg.dynsym.addr;
		dynsym_size = elf.shdr64.sh_size =
		    obj->dynseg.dynstr.addr - obj->dynseg.dynsym.addr;
		elf.shdr64.sh_link = 1;
		elf.shdr64.sh_offset =
		    obj->dynseg.dynsym.addr - elf_text_base(obj);
		elf.shdr64.sh_addralign = sizeof(long);
		elf.shdr64.sh_info = 0;
		elf.shdr64.sh_flags = SHF_ALLOC;
		elf.shdr64.sh_name = soffset;
		elf.shdr64.sh_entsize = sizeof(Elf64_Sym);
		add_section_entry(obj, &elf.shdr64);

		/*
		 * .dynstr
		 */
		if (add_shstrtab_entry(obj, ".dynstr", &soffset) == false) {
			return elf_error_set(e, "add_shstrtab_entry failed");
		}
		elf.shdr64.sh_addr = obj->dynseg.dynstr.addr;
		elf.shdr64.sh_size = obj->dynseg.dynstr.size;
		elf.shdr64.sh_link = 0;
		elf.shdr64.sh_offset = obj->dynseg.dynstr.addr - elf_text_base(obj);
		elf.shdr64.sh_addralign = 1;
		elf.shdr64.sh_info = 0;
		elf.shdr64.sh_flags = SHF_ALLOC;
		elf.shdr64.sh_name = soffset;
		elf.shdr64.sh_entsize = 1;
		add_section_entry(obj, &elf.shdr64);
		/*
		 * NOTE: set the ELF_DYNSYM_F flag so the client code knows
		 * if its able to use the dynamic symbol table.
		 */
		obj->flags |= ELF_DYNSYM_F;

		/*
		 * .got.plt
		 */
		if (add_shstrtab_entry(obj, ".got.plt", &soffset) == false) {
			return elf_error_set(e, "add_shstrtab_entry failed");
		}
		elf.shdr64.sh_addr = obj->dynseg.pltgot.addr;
		/*
		 * GOT should be big enough for 3 reserved entries and
		 * then enough slots for each dynamic symbol.
		 */
		dynsym_count = dynsym_size / sizeof(Elf64_Sym);
		elf.shdr64.sh_size = (sizeof(uintptr_t) * 3) +
		    (sizeof(uintptr_t) * dynsym_count);
		elf.shdr64.sh_link = 0;
		elf.shdr64.sh_offset =
		    (obj->dynseg.pltgot.addr - elf_data_base(obj)) + elf_data_offset(obj);
		elf.shdr64.sh_addralign = sizeof(uintptr_t);
		elf.shdr64.sh_info = 0;
		elf.shdr64.sh_flags = SHF_ALLOC|SHF_WRITE;
		elf.shdr64.sh_name = soffset;
		elf.shdr64.sh_entsize = sizeof(uintptr_t);
		add_section_entry(obj, &elf.shdr64);
		obj->flags |= ELF_PLTGOT_F;
		break;
	default:
		break;
	}
	return sort_elf_sections(obj, e);
}

bool
sort_elf_sections(elfobj_t *obj, elf_error_t *error)
{
	size_t section_count = obj->section_count;
	size_t i;

	obj->sections = (struct elf_section **)
	    malloc(sizeof(struct elf_section *) * (section_count + 1));

	if (obj->sections == NULL) {
		elf_error_set(error, "malloc: %s", strerror(errno));
		return false;
	}
	for (i = 0; i < section_count; i++) {
		obj->sections[i] = malloc(sizeof(struct elf_section));
		if (obj->sections[i] == NULL) {
			elf_error_set(error, "malloc: %s", strerror(errno));
			return false;
		}
		switch(obj->e_class) {
		case elfclass32:
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
		case elfclass64:
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
	return true;
}
