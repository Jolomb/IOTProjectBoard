#include "led_control.h"

#include <ti/drivers/PIN.h>
#include <ti/drivers/pin/PINCC26XX.h>



static PIN_Handle ledPinHandle;
static PIN_State ledPinState;

/*
 * Initial LED pin configuration table
 *   - LEDs Board_PIN_LED0 is on.
 *   - LEDs Board_PIN_LED1 is off.
 */
PIN_Config ledPinTable[] = {
    Board_PIN_LED0 | PIN_GPIO_OUTPUT_EN | PIN_GPIO_LOW | PIN_PUSHPULL | PIN_DRVSTR_MAX,
    Board_PIN_LED1 | PIN_GPIO_OUTPUT_EN | PIN_GPIO_LOW  | PIN_PUSHPULL | PIN_DRVSTR_MAX,
    PIN_TERMINATE
};

void init_LED_pins(){
    ledPinHandle = PIN_open(&ledPinState, ledPinTable);
    if(!ledPinHandle) {
        /* Error initializing board LED pins */
        while(1);
    }

}

void set_red_led(bool on) {
    uint32_t setVal = 0;
    if (on)
        setVal = 1;
    PIN_setOutputValue(ledPinHandle, Board_PIN_LED0, setVal);
}

void set_green_led(bool on) {
    uint32_t setVal = 0;
    if (on)
        setVal = 1;
    PIN_setOutputValue(ledPinHandle, Board_PIN_LED1, setVal);
}

