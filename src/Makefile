# Makefile for libelfmaster

# Configuration
INCLUDE_DIR    = ../include
INSTALL_PREFIX = /opt/elfmaster
INSTALL_LIB    = $(INSTALL_PREFIX)/lib
INSTALL_INC    = $(INSTALL_PREFIX)/include

# Default: glibc-targeted build
CC	= gcc
AR	= ar
ARFLAGS = rcs

# Optional: Override for musl (e.g., make musl MUSL_CC=x86_64-linux-musl-)
MUSL_CC ?= musl-gcc  # Common on systems with musl installed; change if cross-compiling

# Compiler and flags (same for both)
CFLAGS	= -fPIC -ggdb -D_GNU_SOURCE -I$(INCLUDE_DIR)

# Sources and objects
SOURCES = internal.c libelfmaster.c
OBJECTS = $(SOURCES:.c=.o)

# Targets
STATIC_LIB  = libelfmaster.a
SHARED_LIB  = libelfmaster.so

# Default target (glibc)
all: $(STATIC_LIB) $(SHARED_LIB)

# Build static library
$(STATIC_LIB): $(OBJECTS)
	@echo "Building static library $@..."
	$(AR) $(ARFLAGS) $@ $^

# Build shared library
$(SHARED_LIB): $(OBJECTS)
	@echo "Building shared library $@..."
	$(CC) -shared -o $@ $^

# Compile .c to .o
%.o: %.c
	@echo "Compiling $<..."
	$(CC) $(CFLAGS) -c $< -o $@

# Install (glibc build)
install: all
	@echo "Installing to $(INSTALL_PREFIX)..."
	@sudo mkdir -p $(INSTALL_LIB)
	@sudo install -m 644 $(STATIC_LIB) $(INSTALL_LIB)/
	@sudo install -m 755 $(SHARED_LIB) $(INSTALL_LIB)/
	@sudo install -D -m 644 $(INCLUDE_DIR)/libelfmaster.h $(INSTALL_INC)/libelfmaster.h
	@sudo install -D -m 644 $(INCLUDE_DIR)/queue.h $(INSTALL_INC)/queue.h
	@echo "Installation complete."

# Musl-targeted build
musl:
	$(MAKE) all CC=$(MUSL_CC) AR=$(AR) CFLAGS="-DMUSL_BUILD $(CFLAGS)"

musl-install: musl
	@echo "Installing musl-built libraries to $(INSTALL_PREFIX)"
	@sudo mkdir -p $(INSTALL_LIB)
	@sudo install -m 644 $(STATIC_LIB) $(INSTALL_LIB)/
	@sudo install -m 755 $(SHARED_LIB) $(INSTALL_LIB)/
	@sudo install -D -m 644 $(INCLUDE_DIR)/libelfmaster.h $(INSTALL_INC)/libelfmaster.h
	@sudo install -D -m 644 $(INCLUDE_DIR)/queue.h $(INSTALL_INC)/queue.h
	@echo "Musl installation complete."

# Clean build artifacts
clean:
	@echo "Cleaning up..."
	rm -f $(OBJECTS) $(STATIC_LIB) $(SHARED_LIB)

.PHONY: all install musl musl-install clean
