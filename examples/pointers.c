#include <stdio.h>
#include <stdlib.h>

int main(void)
{
	unsigned int value = 33;
	unsigned int *ptr = &value;

	printf("value of value: %u\n", value);
	printf("address of value: %#x\n", &value);
	printf("address of value: %#x\n", ptr);
	printf("value of value: %u\n", *ptr);
}
