#include <elf.h>
#include <link.h>
#include <stdint.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdbool.h>

#define MAX_ERROR_STR_LEN 128

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
};

typedef struct elfobj {
	elf_arch_t arch;
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
	 * Pointers to .dynstr, .strtab, and .shstrtab
	 */
	char *dynstr;
	char *strtab;
	char *shstrtab;
	uint8_t *mem;
	size_t size;
	size_t section_count;
	size_t segment_count;
	size_t note_size;
	size_t dynamic_size;
	size_t eh_frame_size;
} elfobj_t;

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

typedef enum elf_iterator_res {
	ELF_ITER_OK,
	ELF_ITER_DONE,
	ELF_ITER_ERROR
} elf_iterator_res_t;

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
bool get_elf_section_by_name(elfobj_t *, const char *, struct elf_section *);

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

