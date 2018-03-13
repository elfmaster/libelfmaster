all:
	gcc -O2 -g -O2 -fPIC -pie elfparse.c ../src/libelfmaster.a -o elfparse
	gcc -O2 -g ldd.c ../src/libelfmaster.a -o ldd
	gcc -O2 -g plt_dump.c ../src/libelfmaster.a -o plt_dump
	gcc -O2 -g plt_dump2.c ../src/libelfmaster.a -o plt_dump2
	gcc -O2 -g sections.c ../src/libelfmaster.a -o sections
clean:
	rm elfparse ldd plt_dump plt_dump2
