all:
	gcc -Wall main.c -o my_strace
	gcc puts.c -o puts
	gcc fork.c -o fork
