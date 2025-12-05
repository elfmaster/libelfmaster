#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <elf.h>
#include <sys/types.h>
#include <search.h>
#include <sys/time.h>
#include "../include/libelfmaster.h"

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
	elf_plt_iterator_t plt_iter;
	elf_plt_t plt_entry;
	struct elf_mapping mapping;
	struct elf_symbol symbol;
	struct elf_relocation relocation;
	struct elf_shared_object object;
	struct elf_shared_object_iterator so_iter;
	struct timeval tv, tv2;
	unsigned int count = 0;
	bool scop = false;

	if (argc < 2) {
		printf("Usage: elfparse <program>\n");
		return -1;
	}
	if (elf_open_object(argv[1], &obj, ELF_LOAD_F_FORENSICS,
	    &error) == false) {
		printf("%s\n", elf_error_msg(&error));
		return -1;
	}

	if (obj.flags & ELF_SHDRS_F)
		printf("*** Section Headers:\n");
	
	printf("executable base: %#lx\n", elf_executable_text_base(&obj));
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
	}

	if (obj.flags & ELF_PHDRS_F)
		printf("\n*** Program headers\n");

	elf_segment_iterator_init(&obj, &p_iter);
	while (elf_segment_iterator_next(&p_iter, &segment) == ELF_ITER_OK) {
		if (elf_flags(&obj, ELF_SCOP_F) == true && scop == false) {
			printf("SCOP enabled\n");
			scop = true;
		}
		printf("\nAddr:    %#lx\n", segment.vaddr);
		printf("Filesz:  %#lx\n", segment.filesz);
		printf("MemSz:   %#lx\n", segment.memsz);
		printf("Offset:  %#lx\n", segment.offset);
		printf("Align:   %#lx\n", segment.align);
		printf("Type:    %s\n", elf_segment_type_string(segment.type));
	}

	if (obj.flags & ELF_NOTE_F)
		printf("\n*** NOTE Entries\n");
	elf_note_iterator_init(&obj, &n_iter);
	while (elf_note_iterator_next(&n_iter, &note_entry, &error) == ELF_ITER_OK) {
		printf("ELF Note type: %d size: %lu\n", note_entry.type, note_entry.size);
	}

	if (obj.flags & ELF_DYNAMIC_F)
		printf("\n*** Dynamic segment entries\n");

	elf_dynamic_iterator_init(&obj, &d_iter);
	while (elf_dynamic_iterator_next(&d_iter, &dynamic_entry) == ELF_ITER_OK) {
		printf("ELF Dynamic type: %d value: %#lx\n", dynamic_entry.tag, dynamic_entry.value);
	}

	if (obj.flags & ELF_DYNAMIC_F)
		printf("\n*** PLT/GOT table entries\n");

	elf_pltgot_iterator_init(&obj, &pltgot_iter);
	while (elf_pltgot_iterator_next(&pltgot_iter, &pltgot) == ELF_ITER_OK) {
		printf("GOT (%#lx): %#08lx %s\n", pltgot.offset,
		    pltgot.value, elf_pltgot_flag_string(pltgot.flags));
	}
#if 0
	/*
	 * This can only be used when the program calling it is a PIE program, otherwise it will
	 * likely try to map the loadable segments to the address space already in-use by the
	 * calling program. So we comment this out. This function is mostly just good for writing
	 * ELF loaders, like user-land execve's
	 */
	if (elf_map_loadable_segments(&obj, &mapping, &error) == false) {
		printf("failed to load segments: %s\n", elf_error_msg(&error));
	}
#endif
	/*
	 * Just demonstrating how to look up a symbol by name.
	 */
	if (elf_symbol_by_name(&obj, "main", &symbol) == true) {
		printf("\nmain() address: %lx\n", symbol.value);
	}

	if (obj.flags & ELF_DYNSYM_F)
		printf("\n*** Dynamic symbols\n");
	elf_dynsym_iterator_init(&obj, &dsym_iter);
	while (elf_dynsym_iterator_next(&dsym_iter, &symbol) == ELF_ITER_OK) {
		printf("dynsym: %s : %lx\n", symbol.name, symbol.value);
	}

	if (obj.flags & ELF_SYMTAB_F)
		printf("\n*** Symbols\n");
	elf_symtab_iterator_init(&obj, &symtab_iter);
	while (elf_symtab_iterator_next(&symtab_iter, &symbol) == ELF_ITER_OK) {
		printf("symtab: %s : %lx\n", symbol.name, symbol.value);
	}

	printf("\n*** ELF Relocations\n");
	if (elf_relocation_iterator_init(&obj, &reloc_iter) == false) {
		printf("Failed to initialize elf relocation iterator\n");
	} else {
		while (elf_relocation_iterator_next(&reloc_iter, &relocation) == ELF_ITER_OK) {
			printf("\nRelocation symbol: %s\n"
			       "Type:              %s\n"
			       "Section:           %s\n"
			       "Offset:            %lx\n"
			       "Addend:	           %lx\n", relocation.symname, elf_reloc_type_string(&obj, relocation.type),
		    	    relocation.shdrname, relocation.offset, relocation.addend);
		}
	}
	/*
	 * Its very important to be able to correspond calls into the PLT
	 * with an actual symbol, especially when we're working with the PLT/GOT
	 * and wanting to do things like PLT/GOT poisoning detection.
	 */
	if (obj.flags & ELF_PLT_F)
		printf("\n*** ELF PLT entries\n");
	elf_plt_iterator_init(&obj, &plt_iter);
	for (;;) {
		elf_iterator_res_t res;
		res = elf_plt_iterator_next(&plt_iter, &plt_entry);
		if (res == ELF_ITER_DONE)
			break;
		if (res == ELF_ITER_ERROR) {
			printf("plt iterator failed: %s\n", elf_error_msg(&error));
			break;
		}
		printf("PLT Symbol: %s\n", plt_entry.symname);
		printf("PLT Addr: %#lx\n", plt_entry.addr);
	}
	/*
	 * If this is a dynamically linked executable, we can use the
	 * shared object iterator to not only list the DT_NEEDED entries
	 * but we can use the ELF_SO_RESOLVE_ALL_F flag to resolve every
	 * dependency, which is a recursive procedure, and the iterator
	 * actually uses /etc/ld.so.cache just like the dynamic linker
	 * which improves resolution performance by orders of magnitude.
	 */
	if (obj.flags & ELF_DYNAMIC_F)
		printf("\n*** ELF shared object dependency resolution\n");

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

	if (elf_section_by_name(&obj, ".dynamic", &dynamic_section) == false) {
		printf("Couldn't find ELF section: .dynamic\n");
	}

	printf("Dynamic section: %lx\n", dynamic_section.address);
	elf_close_object(&obj);
	return 0;
}	
