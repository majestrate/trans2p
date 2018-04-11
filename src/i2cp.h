#ifndef I2CP_H
#define I2CP_H
#include "common.h"
struct i2cp_state;


typedef void (*i2cp_write_handler)(void *, uint8_t *, uint32_t);

struct i2cp_state * i2cp_state_new(i2cp_write_handler h, void * impl);

void i2cp_offer(struct i2cp_state * state, uint8_t * data , ssize_t sz);

void i2cp_tick(struct i2cp_state * state);


#endif
