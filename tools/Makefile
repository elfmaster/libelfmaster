all:
	gcc -lasan -fsanitize=address -g -fPIC -pie elfparse.c ../src/libelfmaster.a -o elfparse
	gcc -lasan -fsanitize=address -g -fPIC -pie ldd.c ../src/libelfmaster.a -o ldd
clean:
	rm elfparse
