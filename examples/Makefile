all:
	gcc -O2 -g -fPIC -pie elfparse.c ../src/libelfmaster.a -o elfparse
	gcc -O3 -g ldd.c ../src/libelfmaster.a -o ldd
	gcc -O2 -g read_mem.c ../src/libelfmaster.a -o read_mem
	gcc -O2 -g plt_dump.c ../src/libelfmaster.a -o plt_dump
	gcc -O2 -g plt_dump2.c ../src/libelfmaster.a -o plt_dump2
	gcc -O2 -g sections.c ../src/libelfmaster.a -o sections
	gcc -O0 -ggdb symbols.c ../src/libelfmaster.a -o symbols
	gcc -O2 -g eh_frame.c ../src/libelfmaster.a -o eh_frame
	gcc -O2 -g checksec.c ../src/libelfmaster.a -o checksec
	gcc -O2 -g -fPIC -pie test.c -o test_pie
	gcc -O2 -no-pie test.c ../src/libelfmaster.a -o test
	gcc -O2 -fPIC -pie test.c ../src/libelfmaster.a -o test2_pie
	gcc -O2 -no-pie test.c ../src/libelfmaster.a -o test_stripped
	gcc -O2 -no-pie -m32 test.c ../src/libelfmaster.a -o test32bit
	gcc -O2 -fPIC -pie -m32 test.c ../src/libelfmaster.a -o test32bit_pie
	gcc -no-pie -m32 test.c -o test32_stripped
	gcc ../utils/stripx.c -o stripx
	./stripx test_stripped
	./stripx test32_stripped
clean:
	rm elfparse ldd plt_dump plt_dump2 sections eh_frame test test2 test32bit_pie test_pie test_stripped test32bit stripx symbols checksec test32_stripped
