#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
  char *buf = (char *)malloc(128);
  buf[0] = 'S';
  buf[1] = 'E';
  buf[2] = 'C';
  buf[3] = 'R';
  buf[4] = 'E';
  buf[5] = 'T';
  buf[6] = 0;
  printf("%s\n", buf);
  free(buf);
  while(1) {
  
  }
}
