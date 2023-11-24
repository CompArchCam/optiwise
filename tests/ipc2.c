/* ipc2.c
 *
 * A simple, portable C program containing a loop with a peak IPC (instructions
 * per cycle) of around two.  This is due to a long chain of dependent
 * instructions. */

#include <stdlib.h>

#define REPEAT1(x) x
#define REPEAT2(x) REPEAT1(x) REPEAT1(x)
#define REPEAT4(x) REPEAT2(x) REPEAT2(x)
#define REPEAT8(x) REPEAT4(x) REPEAT4(x)
#define REPEAT16(x) REPEAT8(x) REPEAT8(x)
#define REPEAT32(x) REPEAT16(x) REPEAT16(x)
#define REPEAT64(x) REPEAT32(x) REPEAT32(x)
#define REPEAT128(x) REPEAT64(x) REPEAT64(x)

int main(int argc, char **argv) {
  int iterations = argc >= 2 ? atoi(argv[1]) : 10000000;
  if (iterations < 1) iterations = 1;

  register unsigned int result1 = 0;
  register unsigned int result2 = 0;
  register const unsigned int const1 = 0xd88f2b12;
  register const unsigned int const2 = 0x7aa3411f;
  /* loop body should be 256 instructions + a few control flow instructions. */
  for (int i = 0; i < iterations; i++) {
    /* a series of operations that should be one instruction on most targets. */
    REPEAT64(
      result1 += const1;
      result2 += const2;
      result1 ^= const2;
      result2 ^= const1;
    )
  }

  /* volatile here to prevent compiler optimising the loop away. */
  volatile unsigned int answer = result1 ^ result2;
  return 0;
}
