CC=gcc
CC_AARCH64=aarch64-linux-gnu-gcc
all:
x86:
	$(CC) -O0 -g -fPIC -pie elfparse.c ../src/libelfmaster.a -o elfparse
	$(CC) -O0 -g merged.c ../src/libelfmaster.a -o merged
	$(CC) -O0 -g ldd.c ../src/libelfmaster.a -o ldd
	$(CC) -O2 -g read_mem.c ../src/libelfmaster.a -o read_mem
	$(CC) -O2 -g plt_dump.c ../src/libelfmaster.a -o plt_dump
	$(CC) -O2 -g plt_dump2.c ../src/libelfmaster.a -o plt_dump2
	$(CC) -O2 -g sections.c ../src/libelfmaster.a -o sections
	$(CC) -O0 -ggdb symbols.c ../src/libelfmaster.a -o symbols
	$(CC) -O2 -g eh_frame.c ../src/libelfmaster.a -o eh_frame
	$(CC) -O2 -g checksec.c ../src/libelfmaster.a -o checksec
	$(CC) -O2 -g -fPIC -pie test.c -o test_pie
	$(CC) -O2 -no-pie -Wl,-z,noseparate-code test.c ../src/libelfmaster.a -o test
	$(CC) -O2 -fPIC -pie test.c ../src/libelfmaster.a -o test2_pie
	$(CC) -O2 -no-pie test.c ../src/libelfmaster.a -o test_stripped
	$(CC) -O2 -no-pie -Wl,-z,noseparate-code -m32 test.c ../src/libelfmaster.a -o test32bit
	$(CC) -O2 -fPIC -pie -m32 test.c ../src/libelfmaster.a -o test32bit_pie
	$(CC) -no-pie -m32 test.c -o test32_stripped
	$(CC) -m32 -fPIC -pie -Wl,-z,separate-code test.c -o test32_scop
	$(CC) -g objdump_libelfmaster.c ../src/libelfmaster.a -o objdump_elfmaster -lcapstone
	$(CC) -Wl,-z,separate-code,-z,relro,-z,now test.c -o test_scop
	$(CC) -O2 -g modify_symbol.c ../src/libelfmaster.a -o modify_symbol
	$(CC) -O2 -g modify_dynsym.c ../src/libelfmaster.a -o modify_dynsym
	$(CC) -O2 -g modify_segment.c ../src/libelfmaster.a -o modify_segment
	$(CC) -O2 -g modify_section.c ../src/libelfmaster.a -o modify_section
	$(CC) -O2 -g check_static_pie.c ../src/libelfmaster.a -o check_static_pie
	$(CC) -O2 -g scount.c ../src/libelfmaster.a -o scount
	$(CC) ../utils/stripx.c -o stripx
	$(CC) -N -static -m32 -nostdlib nostdlib.c -o nostdlib32
	$(CC) -N -static -nostdlib nostdlib.c -o nostdlib
	$(CC) -O2 -g elf_text.c ../src/libelfmaster.a -o elf_text
	$(CC) -Wl,-z,separate-code test.c -o test_scop_pie
	$(CC) -no-pie -Wl,-z,separate-code test.c -o test_scop_binary
	$(CC) -O2 -g pltgot.c -o pltgot ../src/libelfmaster.a
	$(CC) -O2 -g scop_check.c -o scop_check ../src/libelfmaster.a
	$(CC) phoff.c -o phoff ../src/libelfmaster.a
	./stripx test_stripped
	./stripx test32_stripped
arm:
	$(CC_AARCH64) -O0 -ggdb symbols.c ../src/libelfmaster.a -o symbols
	$(CC_AARCH64) -N -static -nostdlib nostdlib.c -o nostdlib_aarch64
	$(CC_AARCH64) -Wl,-z,separate-code test.c -o test_scop_pie_aarch64
	$(CC_AARCH64) -no-pie -Wl,-z,separate-code test.c -o test_scop_binary_aarch64
	$(CC_AARCH64) -g -fPIC -pie elfparse.c ../src/libelfmaster.a -o elfparse
clean:
	rm elfparse ldd plt_dump plt_dump2 sections eh_frame test test2 test32bit_pie check_static_pie test_pie test_stripped test32bit stripx symbols checksec test32_stripped test_scop_binary elf_text nostdlib nostdlib32 test_scop test32_scop
