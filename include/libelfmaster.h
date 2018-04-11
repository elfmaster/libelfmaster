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

#ifndef PT_PAX_FLAGS
#define PT_PAX_FLAGS  0x65041580
#endif

#ifndef PT_GNU_EH_FRAME
#define PT_GNU_EH_FRAME 0x6474e550
#endif

#ifndef PT_GNU_STACK
#define PT_GNU_STACK 0x6474e551
#endif

#ifndef PT_GNU_RELRO
#define PT_GNU_RELRO 0x6474e552
#endif

#define MAX_VALID_SHNUM 65535 - 1

typedef struct elf_error {
        char string[MAX_ERROR_STR_LEN];
        int _errno;
} elf_error_t;

typedef enum elf_arch {
	i386,
	x64,
	unsupported
} elf_arch_t;

typedef enum elf_class {
	elfclass64,
	elfclass32
} elf_class_t;

typedef enum elf_obj_flags {
	ELF_SYMTAB_F =			(1 << 0),
	ELF_DYNSYM_F =			(1 << 1),
	ELF_PHDRS_F =			(1 << 2),
	ELF_SHDRS_F =			(1 << 3),
	ELF_NOTE_F =			(1 << 4),
	ELF_PLT_RELOCS_F =		(1 << 5),
	ELF_DYN_RELOCS_F =		(1 << 6),
	ELF_TEXT_RELOCS_F =		(1 << 7),
	ELF_PIE_F =			(1 << 8),
	ELF_DYNAMIC_F =			(1 << 9),
	ELF_PLT_F =			(1 << 10),
	ELF_PLTGOT_F =			(1 << 11),
	ELF_DYNSTR_F =			(1 << 12)
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

typedef struct elf_plt {
	char *symname;
	uint64_t addr;
} elf_plt_t;

/*
 * Flags for uint64_t anomalies
 */
#define INVALID_F_SHOFF		(1ULL << 0)
#define INVALID_F_SHSTRNDX	(1ULL << 1)
#define INVALID_F_SHOFFSET	(1ULL << 2)
#define INVALID_F_SHNUM		(1ULL << 3)
#define INVALID_F_SHENTSIZE	(1ULL << 4)
#define INVALID_F_SH_HEADERS	(1ULL << 5)

/*
 * This struct is not meant to access directly. It is an opaque
 * type. It is only accessed directly from within the API code
 * itself (obviously).
 */
typedef struct elfobj {
	elf_arch_t arch;
	elf_class_t e_class;
	elf_obj_flags_t flags;
	unsigned int type;
	unsigned long long int anomalies;
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
	 * Sorted sections
	 */
	struct elf_section **sections;
	/*
	 * Loadable segments (i.e. text, data)
	 */
#define MAX_PT_LOAD 6 /* Should likely never be over 2 or 3 */
#define ELF_PT_LOAD_TEXT_F (1 << 0)
#define ELF_PT_LOAD_DATA_F (1 << 1)
#define ELF_PT_LOAD_MISC_F (1 << 2)
	struct {
		union {
			Elf64_Phdr phdr64;
			Elf32_Phdr phdr32;
		};
		uint32_t flag;
	} pt_load[MAX_PT_LOAD];
	size_t load_count;
	/*
	 * caches
	 */
	struct {
		struct hsearch_data symtab;
		struct hsearch_data dynsym;
		struct hsearch_data plt;
	} cache;
	/*
	 * lists
	 */
	struct {
		LIST_HEAD(elf_symtab_list, elf_symbol_node) symtab;
		LIST_HEAD(elf_dynsym_list, elf_symbol_node) dynsym;
		LIST_HEAD(elf_plt_list, elf_plt_node) plt;
		LIST_HEAD(elf_shared_object_list, elf_shared_object_node) shared_objects;
		LIST_HEAD(elf_section_list, elf_section_node) sections;
	} list;
	/*
	 * dynamic segment values
	 */
	struct {
		struct {
			uint64_t addr;
		} pltgot;
		struct {
			uint64_t size;
		} relent;
		struct {
			uint64_t addr;
			uint64_t size;
			uint32_t type;
		} pltrel;
		struct {
			uint64_t addr;
			uint64_t size;
		} rela;
		struct {
			uint64_t addr;
			uint64_t size;
		} rel;
		struct {
			uint64_t addr;
		} dynsym;

		struct {
			uint64_t addr;
			uint64_t size;
		} dynstr;
		struct {
			uint64_t addr;
		} init;
		struct {
			uint64_t addr;
		} fini;
		struct {
			uint64_t addr;
		} hash;
		bool exists;
	} dynseg;

	/*
	 * Pointers to .dynstr, .strtab, and .shstrtab
	 */
	char *dynstr;
	char *strtab;
	char *shstrtab;
	size_t internal_section_count;
	size_t internal_shstrtab_size;
	size_t strindex; // used only when creating custom strtabs
	size_t shdrindex; // used only when reconstructing sections
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
	uint64_t text_address; /* text base address */
	uint64_t text_offset;
	uint64_t data_address; /* data segment address */
	uint64_t data_offset;
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

typedef struct elf_plt_iterator {
	struct elf_plt_node *current;
} elf_plt_iterator_t;

typedef struct elf_pltgot_iterator {
	unsigned int index;
	elfobj_t *obj;
	void *pltgot;
	size_t wordsize;
	size_t gotsize;
} elf_pltgot_iterator_t;

#define ELF_PLTGOT_RESERVED_DYNAMIC_F 		(1 << 0)
#define ELF_PLTGOT_RESERVED_LINKMAP_F 		(1 << 1)
#define ELF_PLTGOT_RESERVED_DL_RESOLVE_F 	(1 << 2)
#define ELF_PLTGOT_PLT_STUB_F 			(1 << 3)
#define ELF_PLTGOT_RESOLVED_F			(1 << 4)

typedef struct elf_pltgot_entry {
	uint64_t offset;
	uint64_t value;
	uint32_t flags; /* can be set to ELF_PLTGOT_* flags */
} elf_pltgot_entry_t;

typedef enum elf_iterator_res {
	ELF_ITER_OK,
	ELF_ITER_DONE,
	ELF_ITER_ERROR,
	ELF_ITER_NOTFOUND
} elf_iterator_res_t;

typedef struct elf_relocation_iterator {
	unsigned int index;
	elfobj_t *obj;
	LIST_HEAD(elf_rel_helper_list, elf_rel_helper_node) list;
	struct elf_rel_helper_node *current, *head;
} elf_relocation_iterator_t;

/*
 * Resolve basenames to full paths using ld.so.cache parsing
 */
#define ELF_SO_RESOLVE_F (1 << 0)
/*
 * Get all dependencies recursively
 */
#define ELF_SO_RESOLVE_ALL_F (1 << 1)

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
	struct elf_shared_object_node *yield;
	struct hsearch_data yield_cache;
	LIST_HEAD(ldso_cache_yield_list, elf_shared_object_node) yield_list;
	LIST_HEAD(ldso_malloc_list, elf_malloc_node) malloc_list;
} elf_shared_object_iterator_t;

/*
 * API flags for loading.
 */
#define ELF_LOAD_F_STRICT	(1UL << 0) //only load binaries if ALL headers are sane
#define ELF_LOAD_F_SMART 	(1UL << 1) //(implicit flag) load any binary that the kernel can load and reconstruct
					   //--although symbols and sections won't be available... see next flag
#define ELF_LOAD_F_FORENSICS	(1UL << 2) //this flag will fully reconstruct all forensics relevant data similarly
					   //if the section header tables and symbols are missing or are corrupted.
#define ELF_LOAD_F_MODIFY	(1UL << 3) //Used for modifying binaries
#define ELF_LOAD_F_ULEXEC	(1UL << 4) //Used for ulexec based debugging API

/*
 * Loads an ELF object of any type, for reading or modifying.
 * arg1: file path
 * arg2: ELF object handle to be filled in
 * arg3: ELF Load flags (i.e. ELF_LOAD_FLAGS_STRICT|ELF_LOAD_FLAGS_MODIFY)
 * arg4: error object handle to be filled in upon failure.
 */
bool elf_open_object(const char *path, elfobj_t *, uint64_t, elf_error_t *);
void elf_close_object(elfobj_t *);

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

void elf_plt_iterator_init(elfobj_t *, elf_plt_iterator_t *);
elf_iterator_res_t elf_plt_iterator_next(elf_plt_iterator_t *, struct elf_plt *);

/*
 * Lookup a PLT entry by name. Output is stored in 3rd arg
 * elf_plt *entry
 */
bool elf_plt_by_name(elfobj_t *, const char *, struct elf_plt *);

uint64_t elf_entry_point(elfobj_t *);
uint32_t elf_type(elfobj_t *);
uint16_t elf_machine(elfobj_t *);

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

/*
 * API for iterating over an ELF files shared object dependencies
 * arg0: elfobj_t *, ptr to elf descriptor
 * arg1: elf_shared_object_iterator_t *, ptr to iterator descriptor
 * arg2: optional path to ld.so.cache file (uses /etc/ld.so.cache by default)
 * arg3: iterator flags. optional: ELF_SO_RESOLVE_F, ELF_SO_RESOLVE_ALL_F
 * arg4: error descriptor
 */
bool elf_shared_object_iterator_init(elfobj_t *,
    elf_shared_object_iterator_t *, const char *, unsigned int,
    elf_error_t *);

elf_iterator_res_t elf_shared_object_iterator_next(elf_shared_object_iterator_t *,
    struct elf_shared_object *, elf_error_t *);

/*
 * Convert phdr->p_type to string describing segment type, i.e. "DYNAMIC"
 */
const char * elf_segment_type_string(uint32_t);

/*
 * Get pointer to ELF binary location by address
 */
void * elf_address_pointer(elfobj_t *, uint64_t);

void elf_pltgot_iterator_init(elfobj_t *, elf_pltgot_iterator_t *);
elf_iterator_res_t elf_pltgot_iterator_next(elf_pltgot_iterator_t *, elf_pltgot_entry_t *);

/*
 * Get string describing the GOT entry based on elf_pltgot_entry.flags
 */
const char *
elf_pltgot_flag_string(uint32_t);

/*
 * return base address of text or data segment
 */
uint64_t elf_text_base(elfobj_t *);
uint64_t elf_data_base(elfobj_t *);

/*
 * return base offset of text or data segment
 */
uint64_t elf_text_offset(elfobj_t *);
uint64_t elf_data_offset(elfobj_t *);

/*
 * r_type converted to string representing the relocation
 * type; i.e. "R_X86_64_JUMP_SLOT"
 */
const char *
elf_reloc_type_string(elfobj_t *, uint32_t);
#endif
