#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

int main(int argc, char *argv[]) {
  char *secret = (char *)malloc(128);
  while(1) {
     printf("Enter secret: ");
     int readb = scanf ("%100s",secret);
     assert(readb!=EOF);
  }
}
