#ifndef APPLICATION_LED_CONTROL_H_
#define APPLICATION_LED_CONTROL_H_

#include "board.h"

/*
 * Initializes the state of the boards LEDs
 */
void init_LED_pins();

void set_red_led(bool on);
void set_green_led(bool on);

#endif /* APPLICATION_LED_CONTROL_H_ */
