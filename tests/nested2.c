/* nested2.c
 *
 * A simple, portable C program containing a loop with a peak IPC (instructions
 * per cycle) of around one.  The loop should feature up to 3 nested loops each
 * marked with a goto statement.  These goto statements have very distinctive
 * branch probabilities, as noted in the code.  This means the program is best
 * interpreted as 2 nested loops, one of which has three back edges. */

#include <stdlib.h>

#define REPEAT1(x) x
#define REPEAT2(x) REPEAT1(x) REPEAT1(x)
#define REPEAT4(x) REPEAT2(x) REPEAT2(x)
#define REPEAT8(x) REPEAT4(x) REPEAT4(x)
#define REPEAT16(x) REPEAT8(x) REPEAT8(x)
#define REPEAT32(x) REPEAT16(x) REPEAT16(x)

int main(int argc, char **argv) {
  int iterations = argc >= 2 ? atoi(argv[1]) : 10000000;
  if (iterations < 1) iterations = 1;

  register unsigned int result = 0;
  register const unsigned int const1 = 0xd88f2b12;
  register const unsigned int const2 = 0x7aa3411f;
  register const unsigned int const3 = 0xe042c0e6;
  register const unsigned int const4 = 0x5c979e80;
  /* loop body should be 256 instructions + a few control flow instructions. */
  int i = 0;
  while (i < iterations) {
head:
    i++;
    /* a series of operations that should be one instruction on most targets. */
    REPEAT16(
      result += const1;
      result ^= const2;
      result += const3;
      result ^= const4;
    )
    /* branch 1/16 chance taken */
    if (!(result & 0xf0000)) goto head;
    REPEAT16(
      result += const2;
      result ^= const3;
      result += const4;
      result ^= const1;
    )
    /* branch 1/16 chance taken */
    if (!(result & 0xf0)) goto head;
    REPEAT16(
      result += const3;
      result ^= const4;
      result += const1;
      result ^= const2;
    )
    /* branch 15/16 chance taken */
    if (result & 0xf000) goto head;
    REPEAT16(
      result += const4;
      result ^= const1;
      result += const2;
      result ^= const3;
    )
  }

  /* volatile here to prevent compiler optimising the loop away. */
  volatile unsigned int answer = result;
  return 0;
}
