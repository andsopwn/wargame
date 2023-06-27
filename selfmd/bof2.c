// Name: bof2.c
// Compile: gcc -o bof2 bof2.c -fno-stack-protector -no-pie -z execstack -z norelro

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void win() {
    system("/bin/sh");
}

int main() {
    char    buf[0x90];
    printf("Do it to me.\n");

    scanf("%s", buf);
    printf("<< %s\n", buf);
}