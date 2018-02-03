#include "led_control.h"

#include <ti/drivers/PIN.h>
#include <ti/drivers/pin/PINCC26XX.h>
#include <ti/sysbios/knl/Task.h>
#include <time.h>
#include <stdlib.h>
#include <xdc/runtime/system.h>

static PIN_Handle ledPinHandle;
static PIN_State ledPinState;

static PIN_Handle buttonPinHandle;
static PIN_State buttonPinState;

// The semaphore used to interract with the button
Semaphore_Params sem_params;
Semaphore_Handle button_sem;

#define LED_BLINK_TASK_PRIOTITY 1
#define LED_BLINK_TASK_STACK_SIZE 200
Char *ledBlinkTaskStack = NULL;

static Task_Handle ledBlinkTask[2] = { NULL, NULL };
static LED_state_t current_LED_state[2] = { off, off };
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

/*
 * Application button pin configuration table:
 *   - Buttons interrupts are configured to trigger on falling edge.
 */
PIN_Config buttonPinTable[] = {
    Board_PIN_BUTTON0  | PIN_INPUT_EN | PIN_PULLUP | PIN_IRQ_NEGEDGE,
    Board_PIN_BUTTON1  | PIN_INPUT_EN | PIN_PULLUP | PIN_IRQ_NEGEDGE,
    PIN_TERMINATE
};


#define LED_BLINK_INTERVAL 50000

void buttonCallbackFxn(PIN_Handle handle, PIN_Id pinId) {
    CPUdelay(8000*50);
    if (!PIN_getInputValue(pinId)) {
        switch (pinId) {
            case Board_PIN_BUTTON0:
                Semaphore_post(button_sem);
                break;

            case Board_PIN_BUTTON1:
                Semaphore_post(button_sem);
                break;

            default:
                /* Do nothing */
                break;
        }
    }
}

void init_LED_pins(){
    ledPinHandle = PIN_open(&ledPinState, ledPinTable);
    if(!ledPinHandle) {
        /* Error initializing board LED pins */
        System_abort("LED failure");
    }

    buttonPinHandle = PIN_open(&buttonPinState, buttonPinTable);
    if(!buttonPinHandle) {
        /* Error initializing button pins */
        System_abort("Button Failure");
    }

    Semaphore_Params_init(&sem_params);
    button_sem = Semaphore_create(0, &sem_params, NULL);
    if (!button_sem) {
        System_abort("Semaphore failure");
    }
    /* Setup callback for button pins */
    if (PIN_registerIntCb(buttonPinHandle, &buttonCallbackFxn) != 0) {
        /* Error registering button callback function */
        System_abort("Button callback failure");
    }
}

static void led_blink_task_fxn(UArg a0, UArg a1) {
    uint32_t currVal = 0;
    while(1) {
        currVal =  PIN_getOutputValue(a0);
        PIN_setOutputValue(ledPinHandle, a0, !currVal);
        Task_sleep(LED_BLINK_INTERVAL);
    }
}

void set_led(LED_state_t state, PIN_Id pin) {

    uint8_t led_index;
    switch(pin){
        case Board_PIN_LED0:
            led_index = 0;
            break;
        case Board_PIN_LED1:
            led_index = 1;
            break;
    }
    if(current_LED_state[led_index] == state) {
        // This means the state doesn't change. do nothing
        return;
    }

    if (current_LED_state[led_index] == blinking) {
        // Terminate the blinking LED task
        if (ledBlinkTask[led_index]) {
            Task_delete( &ledBlinkTask[led_index] );
            ledBlinkTask[led_index] = NULL;

        }
        if (ledBlinkTaskStack) {
            free(ledBlinkTaskStack);
            ledBlinkTaskStack = NULL;
        }
    }

    Task_Params ledBlinkParams;
    uint32_t setVal = 0;
    // Change to the new requested state
    switch(state){
        case on:
            setVal = 1;
        case off:
            PIN_setOutputValue(ledPinHandle, pin, setVal);
            break;
        case blinking:
            // Configure task
            Task_Params_init(&ledBlinkParams);
            ledBlinkTaskStack = (Char*)calloc(1, LED_BLINK_TASK_STACK_SIZE);
            if (!ledBlinkTaskStack) {
                // Failed to allocate the stack for the Blink task...
                set_red_led(on);
                return;
            }
            ledBlinkParams.stack = ledBlinkTaskStack;
            ledBlinkParams.stackSize = LED_BLINK_TASK_STACK_SIZE;
            ledBlinkParams.priority = LED_BLINK_TASK_PRIOTITY;
            ledBlinkParams.arg0 = pin;

            ledBlinkTask[led_index] = Task_create((Task_FuncPtr)led_blink_task_fxn, &ledBlinkParams, NULL);
            break;
    }

    // Set the new state
    current_LED_state[led_index] = state;
}

void set_red_led(LED_state_t state) {
    set_led(state, Board_PIN_LED0);
}

void set_green_led(LED_state_t state) {
    set_led(state, Board_PIN_LED1);
}


