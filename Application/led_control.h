#ifndef APPLICATION_LED_CONTROL_H_
#define APPLICATION_LED_CONTROL_H_

#include <ti/sysbios/knl/Semaphore.h>

#include "board.h"

// How long we wait for the user to press the button before we indicate too long has passed
#define SIGN_BUTTON_TIMEOUT 5000000

// Expose the semaphore used to wait for the button to be clicked
extern Semaphore_Handle button_sem;

typedef enum LED_state {
    off = 0,
    on,
    blinking
} LED_state_t;

/*
 * Initializes the state of the boards LEDs
 */
void init_LED_pins();

void set_red_led(LED_state_t state);
void set_green_led(LED_state_t state);

#endif /* APPLICATION_LED_CONTROL_H_ */
