#include <stdio.h>

int main() {
    int     i;
    char    p[16] = "abcd";

    for(i = 0 ; i < 30 ; i++) {
        printf("%lx\t| %16lx\t|\n", p + i * 8, *(long*)(p + i * 8));
    }
}