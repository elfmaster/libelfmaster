/*
 * Simple version of strip that removes all section headers and zeroes out
 * the string tables that aren't needed.
 * TODO: 0 out the symbol string table for .symtab
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <errno.h>
#include <fcntl.h>
#include <elf.h>
#include <sys/stat.h>

int main(int argc, char **argv)
{
	uint8_t *mem, *p;
	Elf32_Ehdr *ehdr;
	Elf32_Shdr *shdr;
	Elf64_Ehdr *ehdr64;
	Elf64_Shdr *shdr64;
	struct stat st;
	int fd, i, j;
	char *StringTable, *SymStrTable;
	uint16_t e_mach;
	
	if (argc < 2) {
		fprintf(stderr, "Usage: %s <binary>\n", argv[0]);
		exit(0);
	}

	if ((fd = open(argv[1], O_RDWR)) < 0) {
		perror("open");
		exit(-1);
	}

	if (fstat(fd, &st) < 0) {
		perror("fstat");
		exit(-1);
	}

	mem = mmap(NULL, st.st_size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
	if (mem == MAP_FAILED) {
		perror("mmap");
		exit(-1);
	}

	if (mem[0] != 0x7f && strcmp((char *)&mem[1], "ELF")) {
                fprintf(stderr, "Binary '%s' is not an ELF executable\n", argv[1]);
                exit(-1);
        }

	ehdr = (Elf32_Ehdr *)mem;
	e_mach = ehdr->e_machine;
	switch(e_mach) {
		case EM_X86_64:
			ehdr64 = (Elf64_Ehdr *)mem;
			shdr64 = (Elf64_Shdr *)&mem[ehdr64->e_shoff];

			/*
			 * Erase symbol strings from .symtab
			 */
			for (i = 0; i < ehdr64->e_shnum; i++) {
				if (shdr64[i].sh_type == SHT_SYMTAB) {
		                	SymStrTable = (char *)&mem[shdr64[shdr64[i].sh_link].sh_offset];
					for (p = SymStrTable, j = 0; j < shdr64[shdr64[i].sh_link].sh_size; j++, p++) 
						*p = 0x00; 
					
				}
			}

			/*
	 		 * Erase string names of sections
	 		 */
			for (i = 0, StringTable = (char *)&mem[shdr64[ehdr64->e_shstrndx].sh_offset], p = StringTable; 
			     i < shdr64[ehdr64->e_shstrndx].sh_size; i++, p++)
				*p = 0x00;
		       /*
	 		* Erase section header structs
	 		*/
			for (p = &mem[ehdr64->e_shoff], i = 0; i < ehdr64->e_shentsize * ehdr64->e_shnum; i++, p++)
				*p = 0x00;

			ehdr64->e_shstrndx = 0;
			ehdr64->e_shnum = 0;
			ehdr64->e_shoff = 0;
			break;
		case EM_386:
			ehdr = (Elf32_Ehdr *)mem;
                        shdr = (Elf32_Shdr *)&mem[ehdr->e_shoff];

	                /*
                         * Erase symbol strings from .symtab
                         */
                        for (i = 0; i < ehdr->e_shnum; i++) {
                                if (shdr[i].sh_type == SHT_SYMTAB) {
                                        SymStrTable = (char *)&mem[shdr[shdr[i].sh_link].sh_offset];
                                        for (p = SymStrTable, j = 0; j < shdr[shdr[i].sh_link].sh_size; j++, p++) 
                                                *p = 0x00;

                                }
                        }

                        /*
                         * Erase string names of sections
                         */
                        for (i = 0, StringTable = (char *)&mem[shdr[ehdr->e_shstrndx].sh_offset], p = StringTable;
                             i < shdr[ehdr->e_shstrndx].sh_size; i++, p++)
                                *p = 0x00;
                       /*
                        * Erase section header structs
                        */
                        for (p = &mem[ehdr->e_shoff], i = 0; i < ehdr->e_shentsize * ehdr->e_shnum; i++, p++)
                                *p = 0x00;
			ehdr->e_shstrndx = 0;
                        ehdr->e_shnum = 0;
                        ehdr->e_shoff = 0;
			break;
		default:
			printf("Unsupported machine architecture\n");
			exit(0);
	}

	msync(mem, st.st_size, MS_SYNC);
	munmap(mem, st.st_size);
	close(fd);
	
	
}

