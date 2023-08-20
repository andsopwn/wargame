#include <stdio.h>
#include <stdlib.h>
#include <limits.h>

typedef unsigned long long ull;

void stream_prime(ull pli) {
   ull result, i, j;
   for(i = 2 ; i < pli ; i++) {
      for(j = 2 ; j < i - 1 ; j++, result = j) {}
   }
}

int main(int argc, char** argv) {
   if(argc != 2) {
      printf("Usage : ./prime [number]\n");
      exit(-1);
   }
   ull prime = atoi(argv[1]);
   
   stream_prime(prime);
}