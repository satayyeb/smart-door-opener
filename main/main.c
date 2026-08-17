#include "door_config.h"
#include "door_control.h"
#include "door_socket.h"
#include "door_web.h"
#include "door_wifi.h"
#include "driver/gpio.h"
#include "esp_err.h"
#include "esp_log.h"
#include "esp_system.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "nvs_flash.h"

static const char *TAG = "smart_door";

#define FACTORY_RESET_GPIO GPIO_NUM_0

static void factory_reset_task(void *unused)
{
    (void)unused;
    gpio_config_t config = {
        .pin_bit_mask = 1ULL << FACTORY_RESET_GPIO,
        .mode = GPIO_MODE_INPUT,
        .pull_up_en = GPIO_PULLUP_ENABLE,
        .intr_type = GPIO_INTR_DISABLE,
    };
    ESP_ERROR_CHECK(gpio_config(&config));
    int held_ticks = 0;
    for (;;) {
        if (gpio_get_level(FACTORY_RESET_GPIO) == 0) {
            if (++held_ticks == 1) ESP_LOGW(TAG, "Hold GPIO 0 for 10 seconds to erase configuration");
            if (held_ticks >= 100) {
                ESP_ERROR_CHECK(door_config_erase());
                ESP_LOGW(TAG, "Configuration erased; restarting in setup mode");
                vTaskDelay(pdMS_TO_TICKS(500));
                esp_restart();
            }
        } else {
            if (held_ticks) ESP_LOGI(TAG, "Factory reset cancelled");
            held_ticks = 0;
        }
        vTaskDelay(pdMS_TO_TICKS(100));
    }
}

void app_main(void)
{
    /* Make the relay safe before NVS, Wi-Fi, or any other slow initialization. */
    ESP_ERROR_CHECK(door_control_init());

    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        err = nvs_flash_init();
    }
    ESP_ERROR_CHECK(err);
    ESP_ERROR_CHECK(door_config_init());
    ESP_ERROR_CHECK(door_wifi_start());
    if (!door_config_is_provisioned()) ESP_ERROR_CHECK(door_web_start());
    if (xTaskCreate(factory_reset_task, "factory_reset", 1536, NULL, 2, NULL) != pdPASS)
        ESP_LOGE(TAG, "Could not start factory reset monitor");
    if (door_config_is_provisioned()) {
        err = door_socket_start();
        if (err != ESP_OK) ESP_LOGE(TAG, "WebSocket start failed: %s", esp_err_to_name(err));
    } else {
        ESP_LOGW(TAG, "Not provisioned. Connect to the setup AP and open http://192.168.4.1");
    }
}
