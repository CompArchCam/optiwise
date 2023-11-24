/* recursion-loop.c
 *
 * Sample program that featues a loop containing a recursive function. */ 

#include <stdio.h>
#include <stdlib.h>
#include <limits.h>

unsigned int func1 () {
    volatile unsigned int i = 0; 
    for (int j = 0; j < 50; ++j) // 50000*50 iter by default 
        i += 10; 
    return i; // = 500 
}

void func2 (unsigned int i, volatile unsigned int* res) { // res += i 
    *res += 1; 
    i--; 
    if (i > 0)
        func2(i, res); 
}

int main(int argc, char **argv) {
  int iterations = argc >= 2 ? atoi(argv[1]) : 1000;
  if (iterations < 1) iterations = 1;
  if (iterations >= INT_MAX / sizeof(unsigned int)) return 1;

  /* This will be a simple loop with exactly 'iterations' iterations. */
  volatile unsigned int res1 = 0; 
  for (int i = 0; i < iterations; i++) { // 1000 iter by default 
    res1 += 1; // + 1000
    for (int j = 0; j < 50; ++j) { // 50000 iter by default 
        res1 += func1(); // + 50000*500
    }
    func2(20, &res1); // + 20*1000 by default 
  }

  volatile unsigned int answer = res1; 
  printf("%d\n", answer); // 25021000 
  return 0;
}

