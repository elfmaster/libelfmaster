#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <elf.h>
#include <sys/types.h>
#include <search.h>
#include <sys/time.h>
#include "../include/libelfmaster.h"

const char *
got_flag_str(uint32_t flags)
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

int main(int argc, char **argv)
{
	elfobj_t obj;
	elf_error_t error;
	struct elf_section dynamic_section, section;
	struct elf_segment segment;
	elf_pltgot_iterator_t pltgot_iter;
	elf_pltgot_entry_t pltgot;
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
	struct timeval tv, tv2;
	unsigned int count = 0;

	if (elf_open_object(argv[1], &obj, false, &error) == false) {
		printf("%s\n", elf_error_msg(&error));
		return -1;
	}

	if (obj.flags & ELF_SHDRS_F)
		printf("*** Section Headers:\n");
	/*
	 * The iterator simply won't print anything if there are no sections
	 * so we don't have to nest this block of code
	 */
	elf_section_iterator_init(&obj, &s_iter);
	while (elf_section_iterator_next(&s_iter, &section) == ELF_ITER_OK) {
		struct elf_section tmp_section;

		printf("\nSection %u\n", count++);
		printf("Name: %s\n", section.name ? section.name : "");
		printf("Addr:   %#lx\n", section.address);
		printf("Off:    %#lx\n", section.offset);
		printf("Size:   %#lx\n", section.size);
		printf("Info:   %u\n", section.info);
		printf("Flags:  %C%C%C\n", section.flags & SHF_ALLOC ? 'A' : ' ',
		    section.flags & SHF_EXECINSTR ? 'X' : ' ',
		    section.flags & SHF_WRITE ? 'W' : ' ');
		if (elf_section_by_index(&obj, section.link, &tmp_section) == true) {
			if (tmp_section.name != NULL)
				printf("Link:   %s\n", tmp_section.name);
			else
				printf("Link:   %u\n", section.link);
		} else {
			printf("Link:   %u\n", section.link);
		}
		printf("Align:  %lx\n", section.align);
		printf("EntSiz: %lu\n", section.entsize);
		printf("Index:  %u\n", section.index);
	}

	if (obj.flags & ELF_PHDRS_F)
		printf("\n*** Program headers\n");

	elf_segment_iterator_init(&obj, &p_iter);
	while (elf_segment_iterator_next(&p_iter, &segment) == ELF_ITER_OK) {
		printf("\nAddr:    %#lx\n", segment.vaddr);
		printf("Filesz:  %#lx\n", segment.filesz);
		printf("MemSz:   %#lx\n", segment.memsz);
		printf("Offset:  %#lx\n", segment.offset);
		printf("Align:   %#lx\n", segment.align);
		printf("Type:    %s\n", elf_segment_type_string(segment.type));
	}

	elf_note_iterator_init(&obj, &n_iter);
	while (elf_note_iterator_next(&n_iter, &note_entry) == ELF_ITER_OK) {
		printf("ELF Note type: %d size: %lu\n", note_entry.type, note_entry.size);
	}

	elf_dynamic_iterator_init(&obj, &d_iter);
	while (elf_dynamic_iterator_next(&d_iter, &dynamic_entry) == ELF_ITER_OK) {
		printf("ELF Dynamic type: %d value: %#lx\n", dynamic_entry.tag, dynamic_entry.value);
	}

	elf_pltgot_iterator_init(&obj, &pltgot_iter);
	while (elf_pltgot_iterator_next(&pltgot_iter, &pltgot) == ELF_ITER_OK) {
		printf("GOT (%#lx): %#lx %s\n", pltgot.offset, pltgot.value, got_flag_str(pltgot.flags));
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
	if (elf_shared_object_iterator_init(&obj, &so_iter,
	    NULL, ELF_SO_RESOLVE_ALL_F, &error) == false) {
		printf("elf_shared_object_iterator_init failed: %s\n", elf_error_msg(&error));
	}
	for (;;) {
		elf_iterator_res_t res;
		res = elf_shared_object_iterator_next(&so_iter, &object, &error);
		if (res == ELF_ITER_DONE)
			break;
		if (res == ELF_ITER_ERROR) {
			printf("shared object iterator failed: %s\n", elf_error_msg(&error));
			break;
		}
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
