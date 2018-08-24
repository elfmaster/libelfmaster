#ifndef _ELFMASTER_MD_H
#define	_ELFMASTER_MD_H

#include <elf.h>

#define	R_386_32PLT		 R_386_PLT32
#define	R_386_16		 20
#define	R_386_PC16		 21
#define	R_386_8			 22
#define	R_386_PC8		 23
#define	R_386_SIZE32		 38
#define	R_386_TLS_GOTDESC	 39
#define	R_386_TLS_DESC_CALL	 40
#define	R_386_TLS_DESC		 41

#define	R_X86_64_JUMP_SLOT	 R_X86_64_JMP_SLOT
#define	R_X86_64_RELATIVE64	 38

#endif
