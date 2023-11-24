/* recursion-loop.c
 *
 * Sample program based on real quick sort that featues a recursive function
 * containing a loop. */

#include <stdlib.h>
#include <limits.h>

/* The interesting loops are in this function. */
unsigned int rec_loop_qsort(unsigned int *array, int low, int high);

int main(int argc, char **argv) {
  int iterations = argc >= 2 ? atoi(argv[1]) : 10000000;
  if (iterations < 1) iterations = 1;
  if (iterations >= INT_MAX / sizeof(unsigned int)) return 1;

  unsigned int *array = malloc(iterations * sizeof(unsigned int));

  /* Initialise the array with a simple LCG PRNG. I've not tested the quality of
   * this RNG, but as long as it's not trivially simple it doesn't really
   * matter. */
  array[0] = 0xd88f2b12;
  /* This will be a simple loop with exactly 'iterations' iterations. */
  for (int i = 1; i < iterations; i++) {
    array[i] = (array[i-1] * 0x7aa3411f) + 1;
  }

  /* volatile here to prevent compiler optimising the rec_loop_qsort away. */
  volatile unsigned int answer = rec_loop_qsort(array, 0, iterations);
  return 0;
}

unsigned int rec_loop_qsort(unsigned int *array, int low, int high) {
  unsigned int checksum = 0;
  /* This is the most exciting loop in the program.  In total, it must be
   * entered exactly 'iterations' times because each time it is entered, one
   * element becomes fully sorted (the pivot).  Hence, this loop has
   * 'iterations' iterations total. In terms of iterations per invocation, we'd
   * intuitively expect each entry to have an average of 2 iterations, as half
   * of all pivots will be after some previus pivot. */
  while (low < high) {
    unsigned int pivot = array[low];

    int pindex = low;
    int index = high - 1;
    /* This loop is hard to analyse in terms of number of iterations. It ought
     * to go round half as many times as there are elements on the wrong side of
     * the pivot. */
    while (1) {
      int temp;
      while (array[index] > pivot && index > pindex) index--;
      temp = index;
      if (index == pindex) break;
      array[pindex] = array[index];
      index = pindex + 1;
      pindex = temp;
      while (array[index] < pivot && index < pindex) index++;
      temp = index;
      if (index == pindex) break;
      array[pindex] = array[index];
      index = pindex - 1;
      pindex = temp;
    }
    array[pindex] = pivot;

    checksum ^= pivot + pindex;
    /* This recursive call is what makes this program so tricky for loop
     * analysis; it's effectively a loop to the start of the function, but is
     * nested within the while loop. */
    checksum ^= rec_loop_qsort(array, low, pindex);
    low = pindex + 1;
  }

  return checksum;
}
