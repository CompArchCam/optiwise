/* example.c
 *
 * A simple, portable C program demonstrating the need for CPI analysis.  The
 * program contains a hot loop, with a long cache miss thereafter.  The CPI of
 * the instructions suggests that the load, not the loops, is the problem.
 * per cycle) of around one.  This is due to a long chain of dependent
 * instructions. */

#include <stdlib.h>

/* needs to be bigger than cache. */
#define MEM_SIZE (128 * 1024 * 1024)

int main(int argc, char **argv) {
  int iterations = argc >= 2 ? atoi(argv[1]) : 10000000;
  if (iterations < 1) iterations = 1;

  unsigned int *array = malloc(MEM_SIZE);

  /* Initialise the array with a simple LCG PRNG. I've not tested the quality of
   * this RNG, but as long as it's not trivially simple it doesn't really
   * matter. */
  array[0] = 0xd88f2b12;
  /* This will be a simple loop with exactly 'MEM_SIZE / sizeof(int)' iterations. */
  for (int i = 1; i < MEM_SIZE / sizeof(int); i++) {
    array[i] = (array[i-1] * 0x7aa3411f) + 1;
  }

  register unsigned int result = 0;
  register const unsigned int const1 = 0xd88f2b12;
  register const unsigned int const2 = 0x7aa3411f;
  /* A loop of 'iterations' iterations. */
  for (int i = 0; i < iterations; i++) {
    /* a series of operations that should be one instruction on most targets. */
    /* Inner loop is 256 iterations. */
    for (int j = 0; j < 256; j++) {
      result += const1;
      result ^= const2;
    }
    result ^= array[result % (MEM_SIZE / sizeof(int))];
  }

  /* volatile here to prevent compiler optimising the loop away. */
  volatile unsigned int answer = result;
  return 0;
}
