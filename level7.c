#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

void getinput()
{
  char buffer[64];
  printf("%p\n", buffer); // print address of the beginning of buffer

  printf("> "); 
  fflush(stdout);

  read(0, buffer, 0x120); // overflow happens here

  printf("\ngot input: %s\n", buffer);
}

int main(int argc, char **argv)
{
  getinput();
}