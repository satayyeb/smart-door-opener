#include "door_control.h"

#include <stdbool.h>
#include "driver/gpio.h"
#include "esp_timer.h"

#define RELAY_GPIO GPIO_NUM_12
#define RELAY_ACTIVE_LEVEL 1
#define RELAY_PULSE_US (300 * 1000)

static esp_timer_handle_t s_relay_timer;
static bool s_active;

static void relay_off(void *unused)
{
    (void)unused;
    gpio_set_level(RELAY_GPIO, !RELAY_ACTIVE_LEVEL);
    s_active = false;
}

esp_err_t door_control_init(void)
{
    /* Preload the output latch before enabling the output driver. This avoids a
     * short active pulse while gpio_config() changes the pin direction. */
    gpio_set_level(RELAY_GPIO, !RELAY_ACTIVE_LEVEL);
    gpio_config_t config = {
        .pin_bit_mask = 1ULL << RELAY_GPIO,
        .mode = GPIO_MODE_OUTPUT,
        .pull_up_en = GPIO_PULLUP_DISABLE,
        .pull_down_en = GPIO_PULLDOWN_ENABLE,
        .intr_type = GPIO_INTR_DISABLE,
    };
    ESP_ERROR_CHECK(gpio_config(&config));
    gpio_set_level(RELAY_GPIO, !RELAY_ACTIVE_LEVEL);
    const esp_timer_create_args_t timer_args = { .callback = relay_off, .name = "relay_off" };
    return esp_timer_create(&timer_args, &s_relay_timer);
}

esp_err_t door_control_open(void)
{
    if (s_active) return ESP_ERR_INVALID_STATE;
    s_active = true;
    gpio_set_level(RELAY_GPIO, RELAY_ACTIVE_LEVEL);
    esp_err_t err = esp_timer_start_once(s_relay_timer, RELAY_PULSE_US);
    if (err != ESP_OK) relay_off(NULL);
    return err;
}
