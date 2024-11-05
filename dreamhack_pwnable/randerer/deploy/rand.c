#include <stdio.h>
#include <stdlib.h>
#include <time.h>

long long enoughtime(unsigned int v0) {
    srand(v0);

    long long ex = 0;
    for(int i = 0 ; i < 8 ; i++) {
        ex = (ex << 8) | (unsigned char)rand();
    }
    return ex;
}

/*
void init_canary()
{
  unsigned int v0; // eax
  __int64 v1; // rbx
  int i; // [rsp+Ch] [rbp-14h]

  v0 = time(0LL);
  srand(v0);
  for ( i = 0; i <= 7; ++i )
  {
    v1 = canary << 8;
    canary = v1 | (unsigned __int8)rand();
  }
}
*/