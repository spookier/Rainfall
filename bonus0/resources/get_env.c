#include <stdio.h>
#include <stdlib.h>

int main(void)
{
    char *address = getenv("shellcode");

    if (address == NULL)
    {
        fprintf(stderr, "shellcode is not set\n");
        return 1;
    }

    printf("%p\n", (void *)address);
    return 0;
}
