#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>

#define CLASSIFIER_STR_LEN 1024

static bool
append_string(const char *str, char **save, size_t *len)
{
        char tmp[128];
	int indent = 2;

        if (*save == NULL) {
                *save = calloc(CLASSIFIER_STR_LEN, 1);
                if (*save == NULL)
                        return false;
                *len = 0;
		indent = 0;
        }
 	snprintf(tmp, sizeof(tmp), "%*s%s", indent, "", str);
        if ((*len + strlen(tmp)) >=  CLASSIFIER_STR_LEN - 1)
                return false;
        strcat(*save, tmp);
        *len = strlen(*save);
        return true;
}

const char *items[] = {"test", "test1", "hello", "fuckoff", NULL};
int main(void)
{
	char *string = NULL;
	int i;
	size_t len;
	
	for (i = 0; i < 4; i++) {
		if (append_string(items[i], &string, &len) == false) {
			printf("Failed to append string: %s\n", items[i]);
			exit(-1);
		}
	}
	return 0;
}
