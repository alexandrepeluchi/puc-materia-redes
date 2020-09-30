#include <stdio.h>

int main(void)
{
    unsigned int i, x[65536];
    for (i = 0; i < 65536; i ++) {
        x[i] = i;
        printf("%d", x[i]);
    }
    return 0;
}