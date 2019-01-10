/*
 * NOTE Very quick prototype does not take section header sh_align
 * into consideration so it sometimes shows the wrong instructions
 * on section borders. Also without some tweaking capstone won't
 * show sections that have non-code, so we only get several contiguous
 * sections of code disassembled
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <inttypes.h>

#include "../include/libelfmaster.h"
#include <capstone/capstone.h>

int main(int argc, char **argv)
{
	csh handle;
	cs_insn *insn;
	size_t count;
	elfobj_t obj;
	elf_error_t error;
	struct elf_section section;
	elf_section_iterator_t s_iter;
	uint64_t base_vaddr, base_offset;
	size_t len;
	uint8_t *ptr;
	int i;

	if (argc < 2) {
		printf("Usage: %s <binary>\n", argv[0]);
		exit(EXIT_SUCCESS);
	}
	if (elf_open_object(argv[1], &obj, ELF_LOAD_F_FORENSICS, &error) == false) {
		fprintf(stderr, "%s\n", elf_error_msg(&error));
		return -1;
	}
	elf_section_iterator_init(&obj, &s_iter);
	while (elf_section_iterator_next(&s_iter, &section) == ELF_ITER_OK) {
		if (strcmp(section.name, ".init") == 0) {
			base_vaddr = section.address;
			base_offset = section.offset;
			break;
		}
	}
	len = elf_text_filesz(&obj) + elf_data_filesz(&obj);
	ptr = elf_offset_pointer(&obj, base_offset);
	if (ptr == NULL) {
		printf("Unable to get offset: %lx\n", base_offset);
		return -1;
	}
	if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
		return -1;

	printf("Disassembling %lu bytes\n", len - base_offset);
	count = cs_disasm(handle, ptr, len - base_offset, base_vaddr, base_offset, &insn);
	if (count > 0) {
		size_t j;
		bool checked = false;
		for (j = 0; j < count; j++) {
			char *sname = ".unknown";
			char *symname = "sub_unknown";
			struct elf_symbol symbol;

			if (elf_symbol_by_value(&obj, insn[j].address, &symbol) == true)
				symname = symbol.name;

			if (elf_section_by_address(&obj, insn[j].address, &section) == true)
				sname = section.name;

			printf("%s:%s:0x%"PRIx64":\t%s\t\t%s\n", section.name, symname,
			    insn[j].address, insn[j].mnemonic,
			    insn[j].op_str);
		}
		cs_free(insn, count);
	} else
		printf("ERROR: Failed to disassemble given code!\n");
	cs_close(&handle);

    return 0;
}
