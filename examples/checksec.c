#define _GNU_SOURCE
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <elf.h>
#include <sys/types.h>
#include <string.h>
#include "../include/libelfmaster.h"

/*
 * These flags are to test PaX features if present.
 */
#define PF_PAGEEXEC	(1U << 4) /* PAGEEXEC enabled */
#define PF_SEGMEXEC	(1U << 6) /* SEGMEXEC enabled */
#define PF_MPROTECT	(1U << 8) /* mprotect restrictions to enforce DEP */
#define PF_RANDEXEC	(1U << 10)
#define PF_EMUTRAMP	(1U << 12)
#define PF_RANDMMAP	(1U << 14)

#define PT_PAX_FLAGS	0x65041580

int main(int argc, char **argv)
{
	elfobj_t obj;
	elf_error_t error;
	struct elf_segment segment;
	elf_segment_iterator_t p_iter;
	elf_note_iterator_t n_iter;
	elf_dynamic_iterator_t d_iter;
	elf_dynamic_entry_t dynamic_entry;
	struct elf_symbol symbol;
	elf_linking_type_t link_type;
	bool dynamic = false, relro = false, strict_linking = false, executable_data = false,
	    pax = false, writable_text = false, executable_stack = false, scop = false;
	unsigned int pax_flags;
	char pax_string[256] = {0};

	if (argc < 2) {
		printf("Usage: %s <executable>\n", argv[0]);
		exit(EXIT_SUCCESS);
	}
	/*
	 * We pass the ELF_LOAD_F_FORENSICS flag to direct libelfmaster to reconstruct
	 * any missing section headers and symbols.
	 */
	if (elf_open_object(argv[1], &obj,
	    ELF_LOAD_F_FORENSICS, &error) == false) {
		printf("%s\n", elf_error_msg(&error));
		return -1;
	}
	if (elf_flags(&obj, ELF_SCOP_F) == true)
		printf("SCOP (Secure code partitioning) is enabled\n");

	if ((link_type = elf_linking_type(&obj)) == ELF_LINKING_UNDEF) {
		printf("Object: %s is not an executable or shared library\n", argv[0]);
		exit(EXIT_SUCCESS);
	}
	elf_segment_iterator_init(&obj, &p_iter);
	while (elf_segment_iterator_next(&p_iter, &segment) == ELF_ITER_OK) {
		switch(segment.type) {
		case PT_DYNAMIC:
			dynamic = true;
			break;
		case PT_GNU_RELRO:
			relro = true;
			break;
		case PT_GNU_STACK:
			if (segment.flags & PF_X)
				executable_stack = true;
			break;
		case PT_LOAD:
			if (segment.offset == 0 && (segment.flags & PF_X)) {
				/* Found text segment */
				if (segment.flags & PF_W) {
					writable_text = true;
				}
			} else {
				/* Found data segment */
				if (segment.flags & PF_X) {
					if (segment.flags & PF_W)
						executable_data = true;
				}
			}
			break;
		case PT_PAX_FLAGS:
			pax = true;
			pax_flags = segment.flags;
			break;
		}
	}
	if (link_type == ELF_LINKING_STATIC && relro == true) {
		printf("RELRO: Disabled (not yet supported with -static executable)\n");
	}
	elf_dynamic_iterator_init(&obj, &d_iter);
	while (elf_dynamic_iterator_next(&d_iter, &dynamic_entry) == ELF_ITER_OK) {
		if (dynamic_entry.tag == DT_BIND_NOW)
			strict_linking = true;
		if (dynamic_entry.tag == DT_FLAGS && dynamic_entry.value == DF_BIND_NOW)
			strict_linking = true;
#ifdef DF_1_PIE /* This is a new flag not always present */
		if (dynamic_entry.tag == DT_FLAGS_1 && dynamic_entry.value == DF_1_PIE)
			strict_linking = true;
#endif
	}
	/*
	 * RELRO
	 */
	if (dynamic == true && relro == true) {
		if (strict_linking == true) {
			printf("RELRO: Full RELRO enabled\n");
		} else {
			printf("RELRO: Partial RELRO enabled\n");
		}
	}
	/*
	 * STACK CANARIES
	 */
	if (elf_symbol_by_name(&obj, "__stack_chk_fail", &symbol) == true) {
		printf("Stack canaries: Enabled\n");
	} else {
		printf("Stack canaries: Disabled\n");
	}

	/*
	 * FULL ASLR
	 */
	if (elf_flags(&obj, ELF_FULL_PIE_F) == true) {
		printf("Full ASLR: Enabled\n");
	} else {
		printf("Full ASLR: Disabled\n");
	}
	/*
	 * DEP
	 */
	if (writable_text == true) {
		printf("DEP: Disabled-- text segment is marked writable\n");
	} else if (executable_data == true) {
		printf("DEP: Disabled-- data segment is marked executable\n");
	} else if (executable_data == true && writable_text == true) {
		printf("DEP: Disabled-- text and data segments have insecure permissions\n");
	} else if (pax == true && (pax_flags & PF_MPROTECT)) {
		printf("DEP: Enabled-- with PaX mprotect restrictions\n");
	} else if (elf_class(&obj) == elfclass64) {
		printf("DEP: Enabled-- by default when x86_64 NX bit is set\n");
	} else if (executable_stack == true) {
		printf("DEP: Disabled-- PT_GNU_STACK is marked executable\n");
	} else {
		/*
		 * We can't say for sure with 32bit elf-class since DEP will be enabled
		 * if they are running on an x64 architecture, and won't be otherwise
		 * and e_machine doesn't reflect the machine they are actually running on.
		 */
		printf("DEP: Unknown\n");
	}

	/*
	 * PaX features
	 */
	if (pax == true) {
		size_t len = 0;

		if (pax_flags & PF_MPROTECT) {
			strcpy(pax_string, "|MPROTECT");
			len += strlen("|MPROTECT");
		}
		if (pax_flags & PF_RANDMMAP) {
			strcpy(&pax_string[len], "|RANDMMAP");
			len += strlen("|RANDMMAP");
		}
		if (pax_flags & PF_PAGEEXEC) {
			strcpy(&pax_string[len], "|PAGEEXEC");
			len += strlen("|PAGEEXEC");
		}
		if (pax_flags & PF_SEGMEXEC) {
			strcpy(&pax_string[len], "|SEGMEXEC");
			len += strlen("|SEGMEXEC");
		}
		if (pax_flags & PF_RANDEXEC) {
			strcpy(&pax_string[len], "|RANDEXEC");
			len += strlen("|RANDEXEC");
		}
		if (pax_flags & PF_EMUTRAMP) {
			strcpy(&pax_string[len], "|EMUTRAMP");
			len += strlen("|EMUTRAMP");
		}
		assert(len < sizeof(pax_string) - 1);
		pax_string[len] = '\0';
		printf("PaX: %s\n", pax_string[0] == '\0' ? "None" : pax_string);
	} else {
		printf("PaX: None\n");
	}

	elf_close_object(&obj);
	exit(EXIT_SUCCESS);
	return 0;
}
