all:
	gcc -O2 -g -O2 -fPIC -pie elfparse.c ../src/libelfmaster.a -o elfparse
	gcc -O2 -g -fPIC -pie ldd.c ../src/libelfmaster.a -o ldd
clean:
	rm elfparse
