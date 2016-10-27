#include <elf.h>
#include <link.h>
#include <stdint.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdbool.h>

#define MAX_ERROR_STR_LEN 128

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
} elfobj_t;

typedef struct elf_section_iterator {
	unsigned int index;
	elfobj_t *obj;
} elf_section_iterator_t;

typedef enum elf_iterator_res {
	ELF_ITER_OK,
	ELF_ITER_DONE,
	ELF_ITER_ERROR
} elf_iterator_res_t;
