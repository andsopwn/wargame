#include <stdio.h>
#include <stdlib.h>

typedef unsigned long DWORD;

int main() {
    int     result[0x44] = { 
        0x39, 0xFFFFFF9B, 0x2C, 0xC6, 
        0x59, 0x58, 0x39, 0xAB, 
        0xFFFFFFCE, 0xC6, 0x18C, 0x190, 
        0xFFFFFFDA, 0x73, 0x52, 0x52, 
        0x66, -85, -81, -39, 
        -83, -82, -80, -78, 
        -32, -30, -31, 0x4F, 
        0x53, 0x4C, 0x53, 0x4F, 
        0x57, 0x83, 0x54, 0x59, 
        0x87, 0x0C, 0x13, 0x3E, 
        0x3B, 0x3E, 0x39, 0x3A, 
        0x38, 0x0D, 0x34, 0x958, 
        0x92E, 0xA20, 0x12F3, 0xAF0, 
        0x1452, 0xB94, 0x14B4, 0xA56, 
        0xB9A, 0x63, 0x5F , 0x8F, 
        0x59, 0x8C, 0x89, 0x8C, 
        0x55, 0x24 
        };

    char flag[64];

    flag[0] = result[0] - 9;
    flag[1] = ~result[1];
    flag[2] = result[2] + 4;
    flag[3] = result[3] / 2;
    flag[4] = result[4] - 34;
    flag[5] = result[5] - 40;
    flag[6] = result[6] + 40;
    flag[7] = result[7] / 3;
    flag[8] = ~result[8];
    flag[9] = result[9] / 2;
    flag[10] = result[10] / 4;
    flag[11] = result[11] / 4;
    flag[12] = result[12] + 19;
    flag[13] = result[13] - 17;
    flag[14] = result[14] - 30;
    flag[15] = result[15];

    for(int i = 16 ; i <= 25 ; i++) {
        flag[i] = (char)(~(flag[i] - (i-1)));
    }

    printf("%s\n", flag);
}

/* 


DH{0d0c70a91ccd9b4fda8eedc657580618c37d08dbfbdc9a426c8f9d1674e0dbf0}

*/