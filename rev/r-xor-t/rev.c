#include <stdio.h>

int main() { 
    int     i;
    char    buf[0x42] = "C@qpl==Bppl@<=pG<>@l>@Blsp<@l@AArqmGr=B@A>q@@B=GEsmC@ArBmAGlA=@q";
    char    flag[0x42];
    
    for(i = 0 ; i <= 64 ; i++)
        flag[i] = ((buf[64 - i] ^ 3) & 0x7f) - 13;

    fflush(stdout);
    for(i = 1 ; i <= 64 ; i++) 
        printf("%c", flag[i]);
    puts("");

}
/*

1. 문자열 길이 64s
2. 입력값 +13
3. 0x7f AND Operation
4. 문자열 뒤집기
5. 입력값 ^3
e615b75a4d563ac971466e05641d7aed556b62fcb460b6027f126bff411bfe63

*/