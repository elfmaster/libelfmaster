#ifndef _LIBELFMASTER_H_
#define _LIBELFMASTER_H_

#include <elf.h>
#include <link.h>
#include <stdint.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdbool.h>
#include <search.h>
#include <sys/queue.h>
#include <sys/stat.h>

#define MAX_ERROR_STR_LEN 128

/*
 * In reality will never exceed 2,3, or 4 at the highest.
 */
#define MAX_LOADABLE_MAPPINGS 8

#define ELFNOTE_NAME(_n_) ((unsigned char*)(_n_) + sizeof(*(_n_)))
#define ELFNOTE_ALIGN(_n_) (((_n_)+3)&~3)
#define ELFNOTE_NAME(_n_) ((unsigned char*)(_n_) + sizeof(*(_n_)))
#define ELFNOTE_DESC(_n_) (ELFNOTE_NAME(_n_) + ELFNOTE_ALIGN((_n_)->n_namesz))
#define ELFNOTE32_NEXT(_n_) ((Elf32_Nhdr *)(ELFNOTE_DESC(_n_) + ELFNOTE_ALIGN((_n_)->n_descsz)))
#define ELFNOTE64_NEXT(_n_) ((Elf64_Nhdr *)(ELFNOTE_DESC(_n_) + ELFNOTE_ALIGN((_n_)->n_descsz)))

typedef struct elf_error {
        char string[MAX_ERROR_STR_LEN];
        int _errno;
} elf_error_t;

typedef enum elf_arch {
	i386,
	x64
} elf_arch_t;

typedef enum elf_obj_flags {
	ELF_HAS_SYMTAB =		(1 << 0),
	ELF_HAS_DYNSYM =		(1 << 1),
	ELF_HAS_PHDRS =			(1 << 2),
	ELF_HAS_SHDRS =			(1 << 3),
	ELF_HAS_NOTE =			(1 << 4),
	ELF_HAS_PLT_RELOCS =		(1 << 5),
	ELF_HAS_DYN_RELOCS =		(1 << 6),
	ELF_HAS_TEXT_RELOCS =		(1 << 7)
} elf_obj_flags_t;

/*
 * Portable ELF section type. Contains pointer to
 * actual string. These sections are also stored in
 * a sorted array which can be searched with bsearch
 * by name, address, or offset.
 */
struct elf_section {
	char *name;
	uint32_t type;
	uint32_t link;
	uint32_t info;
	uint64_t flags;
	uint64_t align;
	uint64_t entsize;
	uint64_t offset;
	uint64_t address;
	size_t size;
	unsigned int index;
};

struct elf_segment {
	uint32_t type;
	uint32_t flags;
	uint64_t offset;
	uint64_t paddr;
	uint64_t vaddr;
	uint64_t filesz;
	uint64_t memsz;
	uint64_t align;
	unsigned int index;
};

struct elf_symbol {
	const char *name;
	uint64_t value;
	uint64_t size;
	uint16_t shndx;
	uint8_t bind;
	uint8_t type;
	uint8_t visibility;
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

struct elf_relocation {
	uint64_t offset;
	uint64_t type;
	int64_t addend;
	char *symname;
	char *shdrname;
};

typedef struct elf_mapping {
	uint8_t *mem[MAX_LOADABLE_MAPPINGS];
	unsigned int index;
	unsigned int flags;
	size_t len;
} elf_mapping_t;

typedef struct elf_shared_object {
	const char *basename;
	char *path;
} elf_shared_object_t;

typedef struct elf_shared_object_node {
	const char *basename;
	char *path;
	unsigned int index; // used by elf_shared_object iterator
	LIST_ENTRY(elf_shared_object_node) _linkage;
} elf_shared_object_node_t;

/*
 * This struct is not meant to access directly. It is an opaque
 * type. It is only accessed directly from within the API code
 * itself (obviously).
 */
typedef struct elfobj {
	elf_arch_t arch;
	elf_obj_flags_t flags;
	unsigned int type;
	union {
		Elf32_Ehdr *ehdr32;
		Elf64_Ehdr *ehdr64;
	};
	union {
		Elf32_Phdr *phdr32;
		Elf64_Phdr *phdr64;
	};
	union {
		Elf32_Shdr *shdr32;
		Elf64_Shdr *shdr64;
	};
	union {
		Elf32_Sym *symtab32;
		Elf64_Sym *symtab64;
	};
	union {
		Elf32_Sym *dynsym32;
		Elf64_Sym *dynsym64;
	};
	union {
		Elf32_Dyn *dynamic32;
		Elf64_Dyn *dynamic64;
	};
	union {
		Elf32_Nhdr *note32;
		Elf64_Nhdr *note64;
	};
	void *eh_frame;
	/*
	 * Sorted sections and segments
	 */
	struct elf_section **sections;
	struct elf_segment **segments;

	/*
	 * caches
	 */
	struct {
		struct hsearch_data symtab;
		struct hsearch_data dynsym;
	} cache;
	/*
	 * lists
	 */
	struct {
		LIST_HEAD(elf_symtab_list, elf_symbol_node) symtab;
		LIST_HEAD(elf_dynsym_list, elf_symbol_node) dynsym;
		LIST_HEAD(elf_shared_object_list, elf_shared_object_node) shared_objects;
	} list;
	/*
	 * dynamic segment values
	 */
	struct {
		struct {
			uint64_t addr;
		} pltgot;

		struct {
			uint64_t addr;
			uint64_t size;
			uint32_t type;
		} pltrel;

		struct {
			uint64_t addr;
		} dynsym;

		struct {
			uint64_t addr;
		} dynstr;
		struct {
			uint64_t addr;
		} init;
		struct {
			uint64_t addr;
		} fini;
	} dynseg;

	/*
	 * Pointers to .dynstr, .strtab, and .shstrtab
	 */
	char *dynstr;
	char *strtab;
	char *shstrtab;
	uint8_t *mem;
	size_t size;
	size_t section_count;
	size_t segment_count;
	size_t symtab_count;
	size_t dynsym_count;
	size_t note_size;
	size_t dynamic_size;
	size_t eh_frame_size;
	uint64_t entry_point;
} elfobj_t;

/*
 * Iterator types.
 */
typedef struct elf_section_iterator {
	unsigned int index;
	elfobj_t *obj;
} elf_section_iterator_t;

typedef struct elf_segment_iterator {
	unsigned int index;
	elfobj_t *obj;
} elf_segment_iterator_t;

typedef struct elf_note_iterator {
	unsigned int index;
	elfobj_t *obj;
	union {
		Elf32_Nhdr *note32;
		Elf64_Nhdr *note64;
	};
} elf_note_iterator_t;

typedef struct elf_note_entry {
	unsigned int type;
	size_t size;
	void *mem;
} elf_note_entry_t;

typedef struct elf_dynamic_iterator {
	unsigned int index;
	elfobj_t *obj;
} elf_dynamic_iterator_t;

typedef struct elf_dynamic_entry {
	unsigned int tag;
	uint64_t value;
} elf_dynamic_entry_t;

typedef struct elf_symtab_iterator {
	struct elf_symbol_node *current;
} elf_symtab_iterator_t;

typedef struct elf_dynsym_iterator {
	struct elf_symbol_node *current;
} elf_dynsym_iterator_t;

typedef enum elf_iterator_res {
	ELF_ITER_OK,
	ELF_ITER_DONE,
	ELF_ITER_ERROR
} elf_iterator_res_t;

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

typedef struct elf_relocation_iterator {
	unsigned int index;
	elfobj_t *obj;
	LIST_HEAD(elf_rel_helper_list, elf_rel_helper_node) list;
	struct elf_rel_helper_node *current;
} elf_relocation_iterator_t;

#define ELF_LDSO_CACHE_OLD (1 << 0)
#define ELF_LDSO_CACHE_NEW (1 << 1)

/*
 * Resolve basenames to full paths using ld.so.cache parsing
 */
#define ELF_SO_RESOLVE (1 << 0)
/*
 * Get all dependencies recursively
 */
#define ELF_SO_RESOLVE_ALL (1 << 1)

typedef struct elf_shared_object_iterator {
	unsigned int index;
	elfobj_t *obj;
	int fd;
	void *mem;
	struct stat st;
	struct cache_file *cache;
	struct cache_file_new *cache_new;
	char *cache_data;
	size_t cache_size;
	uint32_t flags;
	uint32_t cache_flags;
	bool resolve;
	struct elf_shared_object_node *current;
} elf_shared_object_iterator_t;

/*
 * Loads an ELF object of any type, for reading or modifying.
 * arg1: file path
 * arg2: ELF object handle to be filled in
 * arg3: Going to modify this object? true/false
 * arg4: error object handle to be filled in upon failure.
 */
bool load_elf_object(const char *path, elfobj_t *, bool, elf_error_t *);

/*
 * Returns a string containing an error message for any failed libelfmaster
 * API functions.
 */
const char * elf_error_msg(elf_error_t *);

/*
 * Fills in 'struct elf_section *'  on success.
 * Performs a binary search on sorted section headers.
 */
bool elf_section_by_name(elfobj_t *, const char *, struct elf_section *);

/*
 * Fills in 'struct elf_section *' on success.
 */
bool elf_section_by_index(elfobj_t *, unsigned int index, struct elf_section *);


/*
 * ELF Section iterator
 * Iterates over each section header, filling in a struct elf_section upon each
 * iteration.
 */
void elf_section_iterator_init(elfobj_t *, elf_section_iterator_t *);
elf_iterator_res_t elf_section_iterator_next(elf_section_iterator_t *, struct elf_section *);

/*
 * ELF Segment (Program header) iterator
 * Iterates over each program header (which describe segment), filling in a struct elf_segment
 * upon each successful iteration.
 */
void elf_segment_iterator_init(elfobj_t *, elf_segment_iterator_t *);
elf_iterator_res_t elf_segment_iterator_next(elf_segment_iterator_t *, struct elf_segment *);

bool elf_note_iterator_init(elfobj_t *, elf_note_iterator_t *);
elf_iterator_res_t elf_note_iterator_next(elf_note_iterator_t *, elf_note_entry_t *);

void elf_dynamic_iterator_init(elfobj_t *, elf_dynamic_iterator_t *);
elf_iterator_res_t elf_dynamic_iterator_next(elf_dynamic_iterator_t *, elf_dynamic_entry_t *);

void elf_symtab_iterator_init(elfobj_t *, elf_symtab_iterator_t *);
elf_iterator_res_t elf_symtab_iterator_next(elf_symtab_iterator_t *, struct elf_symbol *);

void elf_dynsym_iterator_init(elfobj_t *, elf_dynsym_iterator_t *);
elf_iterator_res_t elf_dynsym_iterator_next(elf_dynsym_iterator_t *, struct elf_symbol *);

uint64_t elf_entry_point(elfobj_t *);
uint32_t elf_type(elfobj_t *);

bool elf_map_loadable_segments(elfobj_t *, struct elf_mapping *, elf_error_t *);

/*
 * Fill in elf_symbol, through cache lookup by name.
 */
bool elf_symbol_by_name(elfobj_t *, const char *, struct elf_symbol *);

bool elf_symbol_by_index(elfobj_t *, unsigned int, struct elf_symbol *, const int);

/*
 * Return a pointer to an offset into the memory mapped ELF file.
 */
void * elf_offset_pointer(elfobj_t *, uint64_t);

/*
 * Return a pointer to the section passed in arg2.
 * This function takes either a pointer to an Elf32_Shdr
 * or an Elf64_Shdr as the second argument, and then uses
 * the sh_offset field to locate the section within the ELF
 * file, then returns a pointer to it.
 */
void * elf_section_pointer(elfobj_t *, void *);

/*
 * Success: returns section name
 * failure: returns NULL
 */
const char * elf_section_name_by_index(elfobj_t *, uint32_t);
/*
 * initialize the relocation iterator.
 */
bool elf_relocation_iterator_init(elfobj_t *, struct elf_relocation_iterator *);

/*
 * iterate over every relocation entry in the entire ELF file. The elf_relocation struct
 * is filled in upon each iteration, and it gives lots of information including which
 * section the relocation applies to, which symbol, and what type of relocation it is.
 */
bool
elf_relocation_iterator_init(struct elfobj *,
    struct elf_relocation_iterator *);

elf_iterator_res_t
elf_relocation_iterator_next(elf_relocation_iterator_t *, struct elf_relocation *);

/*
 * return pointer to string table index for ELF sections (.shstrtab)
 * dynamic symbols (.dynstr) and local symbols (.strtab)
 */
const char * elf_section_string(elfobj_t *, uint64_t);
const char * elf_dynamic_string(elfobj_t *, uint64_t);
const char * elf_symtab_string(elfobj_t *, uint64_t);

bool elf_shared_object_iterator_init(elfobj_t *,
    elf_shared_object_iterator_t *, elf_error_t *);
elf_iterator_res_t elf_shared_object_iterator_next(elf_shared_object_iterator_t *,
    struct elf_shared_object *, elf_error_t *);

#endif
