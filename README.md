# libelfmaster

## Secure ELF parsing library

libelfmaster is a C library for loading and parsing ELF objects
of any type. The goal of this project was to create an API that
is innovative in its ability to be user-friendly, secure, and
provide a variety of creative and useful ways to access an ELF
object. In Addition, I wanted to make a library that could
seamlessly load both 32bit and 64bit ELF objects, vs. having to compile 
two seperate libs for each architecture. The downfall obviously
being that this won't compile on 32bit machines.

## Current status

Work in progress. Not fully fuzzed or tested.

## API Documentation

The best documentation is to read the code in libelfmaster/examples.
elfparse.c is a simple version of readelf, but does not utilize every
API function so make sure to look at all examples.

```
bool elf_open_object(const char *path, elfobj_t *obj,
    elf_error_t *error);
```

Open an ELF object, and fill in the `elfobj_t` descriptor which is
then passed to all subsequent API functions.

`const char *path` is the path to the ELF object

`elfobj_t *obj` is a pointer to the ELF descriptor that will be filled in upon successful
return.

`elf_error_t *error` is filled in with the proper error code and message string upon failure.

*RETURN*

Function returns true on success, and false on failure. `elf_error_t *error` points to the error
information that is filled in upon failure.

*EXAMPLE:*

```
if (elf_open_object("/bin/ls", &obj, false, &err) == false) {
	fprintf(stderr, "failed: %s\n", elf_error_msg(&err));
	return -1;
}
```

