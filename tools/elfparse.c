#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <elf.h>
#include <sys/types.h>
#include <search.h>
#include "../include/libelfmaster.h"

int main(int argc, char **argv)
{
	elfobj_t obj;
	elf_error_t error;
	struct elf_section dynamic_section, section;
	struct elf_segment segment;
	elf_symtab_iterator_t symtab_iter;
	elf_section_iterator_t s_iter;
	elf_segment_iterator_t p_iter;
	elf_note_iterator_t n_iter;
	elf_note_entry_t note_entry;
	elf_dynamic_iterator_t d_iter;
	elf_dynamic_entry_t dynamic_entry;
	elf_dynsym_iterator_t dsym_iter;
	elf_relocation_iterator_t reloc_iter;
	struct elf_mapping mapping;
	struct elf_symbol symbol;
	struct elf_relocation relocation;
	struct elf_shared_object object;
	struct elf_shared_object_iterator so_iter;

	printf("Opening %s\n", argv[1]);
	if (load_elf_object(argv[1], &obj, false, &error) == false) {
		printf("%s\n", elf_error_msg(&error));
		return -1;
	}

	elf_section_iterator_init(&obj, &s_iter);
	while (elf_section_iterator_next(&s_iter, &section) == ELF_ITER_OK) {
		printf("ELF Section: %s : %#lx\n", section.name, section.address);
	}

	elf_segment_iterator_init(&obj, &p_iter);
	while (elf_segment_iterator_next(&p_iter, &segment) == ELF_ITER_OK) {
		printf("ELF Segment: %#08lx - loadable? '%s'\n",
		    segment.vaddr, segment.type == PT_LOAD ? "Yes" : "No");
	}

	elf_note_iterator_init(&obj, &n_iter);
	while (elf_note_iterator_next(&n_iter, &note_entry) == ELF_ITER_OK) {
		printf("ELF Note type: %d size: %u\n", note_entry.type, note_entry.size);
	}

	elf_dynamic_iterator_init(&obj, &d_iter);
	while (elf_dynamic_iterator_next(&d_iter, &dynamic_entry) == ELF_ITER_OK) {
		printf("ELF Dynamic type: %d value: %#lx\n", dynamic_entry.tag, dynamic_entry.value);
	}

#if 0
	if (elf_map_loadable_segments(&obj, &mapping, &error) == false) {
		printf("failed to load segments: %s\n", elf_error_msg(&error));
	}
#endif
	if (elf_symbol_by_name(&obj, "main", &symbol) == true) {
		printf("symbol addr: %lx\n", symbol.value);
	}

	elf_dynsym_iterator_init(&obj, &dsym_iter);
	while (elf_dynsym_iterator_next(&dsym_iter, &symbol) == ELF_ITER_OK) {
		printf("dynsym: %s : %lx\n", symbol.name, symbol.value);
	}

	elf_symtab_iterator_init(&obj, &symtab_iter);
	while (elf_symtab_iterator_next(&symtab_iter, &symbol) == ELF_ITER_OK) {
		printf("symtab: %s : %lx\n", symbol.name, symbol.value);
	}

	elf_relocation_iterator_init(&obj, &reloc_iter);
	while (elf_relocation_iterator_next(&reloc_iter, &relocation) == ELF_ITER_OK) {
		printf("Relocation symbol: %s section: %s offset: %lx\n", relocation.symname,
		    relocation.shdrname, relocation.offset);
	}
	elf_shared_object_iterator_init(&obj, &so_iter, &error);
	while (elf_shared_object_iterator_next(&so_iter, &object, &error) == ELF_ITER_OK) {
		printf("Basename: %s path: %s\n", object.basename, object.path);
	}
	/*
	 * Uses a sorted array of pointers to elf_section structs, and therefore is able
	 * to perform a binary search for faster lookups.
	 */
	if (elf_section_by_name(&obj, ".dynamic", &dynamic_section) == false) {
		printf("Couldn't find ELF section: .dynamic\n");
	}

	printf("Dynamic: %lx\n", dynamic_section.address);
	return 0;
}	

