#include "util.h"
#include <stdio.h>

void hexdump(uint8_t * ptr, uint32_t sz)
{
  uint32_t idx = 0;
  while(idx < sz)
  {
    printf("%02x ", ptr[idx++]);
    if(idx % 8 == 0) printf("\n");
  }
  printf("\n");

}
