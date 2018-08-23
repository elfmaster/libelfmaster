all:
	gcc -O2 -g -O2 -fPIC -pie elfparse.c ../src/libelfmaster.a -o elfparse
	gcc -O3 -g ldd.c ../src/libelfmaster.a -o ldd
	gcc -O2 -g plt_dump.c ../src/libelfmaster.a -o plt_dump
	gcc -O2 -g plt_dump2.c ../src/libelfmaster.a -o plt_dump2
	gcc -O2 -g sections.c ../src/libelfmaster.a -o sections
	gcc -O2 -g symbols.c ../src/libelfmaster.a -o symbols
	gcc -O2 -g eh_frame.c ../src/libelfmaster.a -o eh_frame
	gcc -O2 -no-pie test.c ../src/libelfmaster.a -o test
	gcc -O2 test.c ../src/libelfmaster.a -o test2
clean:
	rm elfparse ldd plt_dump plt_dump2 sections
