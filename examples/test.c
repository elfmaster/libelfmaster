#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(void)
{
	char buf[44];

	strcpy(buf, "hi");
	printf("yo man\n");
	pause();
}
