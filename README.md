# libelfmaster
## Update as of 11/17/18 -- I have a local branch with many new fixes that will be finished and committed by the end of December, been very busy.

## Secure ELF parsing library

libelfmaster is a C library for loading and parsing ELF objects
of any type. The goal of this project was to create an API that
is innovative in its ability to be user-friendly, secure, and
provide a variety of creative and useful ways to access an ELF
object. Not only that, but this library was largley created for
designing reverse engineering applications. This library is capable
of loading binaries with corrupted section headers and it will forensically
reconstruct section headers and symbol tables using state-of-the-art
techniques, such as PT_GNU_EH_FRAME reconstruction for .symtab functions.
This library is also capable of seamlessly loading both 32bit and 64bit
ELF objects, vs. having to compile  two seperate libs for each
architecture. The downfall obviously being that this won't compile on
32bit machines. I am now a guide on this project, as I put it into
the hands of the security and reverse engineering community. I am
currently using it to build https://github.com/elfmaster/elf.arcana
which is advancing the state of Linux/UNIX binary forensics and HIDS.
As I build Arcana, more edge cases come up.


## Future Goals

1. Userland debugging (non-ptrace) API similar to eresi e2dbg
2. ELF patching, and injection. i.e. relocatable code injection + function hijacking etc.
3. Dwarf VM bytecode injection similar to Sergey Bratus and James Oakley's Katana project
4. Continuous advancement of forensically reconstructing all edge cases of broken binaries
5. Explicit support for FreeBSD
6. Explicit support for sparc, mips, arm, etc. Currently it implicitly supports many of the features
7. A regression test suite
8. Better Support for core-files, i.e. forensics reconstruction
9. API Documentation

## Current status

Work in progress. Not fully fuzzed or tested. Needs adept ELF hackers
and reverse engineers with a strong C skills. Has undergone several iterations
of fuzzing done with AFL. Currently I am fixing and patching the code and a new
alpha release tag will be committed pushed soon (By mid October 2018)
Thank you to all who have contributed their fuzzing efforts. I will create a
proper area to name those who should be listed as contributors (Perhaps an Authors file).


## Rules of development

NetBSD coding style, submit a PR for review.

## API Documentation

The best documentation is to read the code in libelfmaster/examples.
elfparse.c is a simple version of readelf, but does not utilize every
API function so make sure to look at all examples. This API needs someone
to document it. 

