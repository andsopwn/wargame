// gcc ooo.c -o ooo -O0 -fno-stack-protector
#include <stdio.h>

int main() {
    char    a[0x20];
    char    b[0x40];

    read(0, a, 0x40);
    read(0, b, 0x60);
}
