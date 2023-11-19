// compile : gcc -no-pie -z norelro -z execstack cnry.c -o cnry

#include <stdio.h>
#include <unistd.h>

void do_me() {
    printf("YOU TOUCHED!\n");
}

int main() {
    char    buf[0x40];

    setvbuf(stdin, 0, _IONBF, 0);
    setvbuf(stdout, 0, _IONBF, 0);
    
    printf("Leak: ");
    read(0, buf, 0x100);
    printf("%s", buf);
    
    printf("Exploit: ");
    read(0, buf, 0x100);
}
