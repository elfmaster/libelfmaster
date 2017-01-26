# libelfmaster

## Secure ELF parsing library

libelfmaster is a C library for loading and parsing ELF objects of any type. The goal of this
project was to create an API that is innovative in its ability to be user-friendly, secure, and
provide a variety of creative and useful ways to access an ELF object. In Addition, I wanted to
make a library that could seamlessly load both 32bit and 64bit ELF objects, vs. having to compile
both a 32bit and 64bit build of the library. The only unfortunate side-effect for some will be that
this library only builds on 64bit architecture.

## Current status

This is a work in progress, and I have decided to release a preliminary version of the library.
It has not yet been proven to be secure, but further testing on security and performance will
be documented soon.

## API Documentation


bool elf_open_object(const char *path, elfobj_t *obj, bool modify,
    elf_error_t *error);

Open an ELF object, and fill in the `elfobj_t` descriptor which is then passed to all subsequent
API functions.

`const char *path` is the path to the ELF object

`elfobj_t *obj` is a pointer to the ELF descriptor that will be filled in upon successful
return.

`bool modify` is currently unused, but is ultimately going to be used when the API is capable
of modifying ELF objects. Currently it is a read-only parsing library.

`elf_error_t *error` is filled in with the proper error code and message string upon failure.

*RETURN*

Function returns true on success, and false on failure. `elf_error_t *error` points to the error
information that is filled in upon failure.

*EXAMPLE:*

```
if (elf_open_object("/bin/ls", &obj, false, &err) == false)
	return -1;
```

