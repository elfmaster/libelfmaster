#ifndef _LIBELFMASTER_INTERNAL_H_
#define _LIBELFMASTER_INTERNAL_H_

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

/*
 * This struct is used internally only.
 */
struct elf_rel_helper_node {
	union {
		Elf32_Rel *rel32;
		Elf64_Rel *rel64;
	};
	union {
		Elf32_Rela *rela32;
		Elf64_Rela *rela64;
	};
	size_t size;
	bool addend;
	char *section_name;
	LIST_ENTRY(elf_rel_helper_node) _linkage;
};

/*
 * This should only be used internally.
 */
struct elf_symbol_node {
	const char *name;
	uint64_t value;
	uint64_t size;
	uint16_t shndx;
	uint8_t bind;
	uint8_t type;
	uint8_t visibility;
	LIST_ENTRY(elf_symbol_node) _linkage;
};

typedef struct elf_shared_object_node {
	const char *basename;
	char *path;
	unsigned int index; // used by elf_shared_object iterator
	LIST_ENTRY(elf_shared_object_node) _linkage;
} elf_shared_object_node_t;

typedef struct elf_plt_node {
	char *symname;
	uint64_t addr;
	LIST_ENTRY(elf_plt_node) _linkage;
} elf_plt_node_t;


static bool
elf_error_set(elf_error_t *, const char *, ...);

static int
section_name_cmp(const void *, const void *);

static bool
build_plt_data(struct elfobj *);

static bool
build_dynsym_data(struct elfobj *);

static bool
build_symtab_data(struct elfobj *);

static int
ldso_cache_cmp(const char *, const char *);

static inline bool
ldso_cache_check_flags(struct elf_shared_object_iterator *, uint32_t);

static const char *
ldso_cache_bsearch(struct elf_shared_object_iterator *,
    const char *);

static bool
ldso_insert_yield_entry(struct elf_shared_object_iterator *,
    const char *);

static bool
ldso_recursive_cache_resolve(struct elf_shared_object_iterator *,
    const char *);

static bool
load_dynamic_segment_data(struct elfobj *);

static void
free_lists(elfobj_t *);

static void
free_caches(elfobj_t *);

static void
free_arrays(elfobj_t *);


#endif // _LIBELFMASTER_INTERNAL_H_
