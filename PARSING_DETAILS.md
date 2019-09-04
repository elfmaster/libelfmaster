## LibElfmaster Parsing Details

It is the goal of libelfmaster to accomplish the already existing goals that
have been outlined -- be the most sophisticated and secure parser for forensics
reconstruction of all binaries, including anomalous ones.

## SCOP (Secure code partitioning)
```
--1/15/2019

The text segment is partitioned into 3 PT_LOAD segment's, although the way its
actually partitioned is contingent upon the linker, /bin/ld, which looks at the
section header sh_flags, i.e. SHN_ALLOC is put into PF_R segment, whereas
SHN_ALLOC|SHN_EXECINSTR is put into a PF_R|PF_X segment, so it is conceivable
that depending on the ordering there could be only two PT_LOAD segments for the
text, or even 4 PT_LOAD segments for the text, as the linker applies these
PT_LOAD partitions in the order that it reads the section headers.

uint64_t elf_text_base(elfobj_t *) previously this returned the base
address of the first PT_LOAD at offset 0, or that is the first PF_R|PF_X. Now
we must consider how to handle SCOP binaries. Here is my proposition:

Based on testing if (elf_flags(obj, ELF_SCOP_F)``` which denotes that SCOP
is in enabled...

uint64_t elf_text_base() gives the base address of the first PT_LOAD
which is probably PF_R.  We then have elf_executable_text_base() which will
return the (In most cases) second load segment base, which is the one that's
actually executable. And elf_executable_text_offset() to return the offset
of the executable part of the text segment.

We have also had size_t elf_text_filesz(elfobj_t *) which returns the
p_filesz of the text segment.  We now have in addition  ssize_t
elf_scop_text_filesz(elfobj_t *) which returns -1 otherwise it returns the
size of all of the LOAD segments that relate to the partitioned text segments.
i.e. it adds them all up and gives the sum total.

Status: Finished
TODO: Handle SCOP scenarios where one of the PT_LOAD's (Say out of 3) have been modified
to be executable, i.e. phdr[text + 0] |= PF_X; which will throw off the way that
libelfmaster handles SCOP parsing. This is an easy fix in ELF_LOAD_F_STRICT_F cases
because we can simply follow the sh_flags of the section headers to see which corresponding
segments (To SHN_ALLOC, SHN_ALLOC|SHN_EXECINSTR) etc. just like the linker does, but for
forensics mode this doesn't cut it. More heuristics to be added.
```
## Handle gcc -nostdlib -N -static t.c -o t binaries
```
Single PT_LOAD segments of RWX usually have a p_vaddr that is not page aligned,
but will be at runtime. This also causes issues with many parsers.  We
currently must handle this more appropriately.
```
