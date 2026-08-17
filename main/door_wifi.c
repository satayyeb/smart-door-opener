#include "door_wifi.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "door_config.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "driver/gpio.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "tcpip_adapter.h"

static const char *TAG = "wifi";

#define STATUS_LED_GPIO GPIO_NUM_2
#define STATUS_LED_ON_LEVEL 0
#define STATUS_LED_BLINK_MS 500

static volatile bool s_connected;
static volatile bool s_websocket_connected;
static volatile bool s_selecting_network;

static void status_led_set(bool on)
{
    gpio_set_level(STATUS_LED_GPIO, on ? STATUS_LED_ON_LEVEL : !STATUS_LED_ON_LEVEL);
}

static void status_led_task(void *unused)
{
    (void)unused;
    bool blink_on = false;
    for (;;) {
        if (!s_connected) {
            status_led_set(true);
        } else if (!s_websocket_connected) {
            blink_on = !blink_on;
            status_led_set(blink_on);
        } else {
            status_led_set(false);
        }
        vTaskDelay(pdMS_TO_TICKS(STATUS_LED_BLINK_MS));
    }
}

static void wifi_event(void *arg, esp_event_base_t base, int32_t id, void *data)
{
    (void)arg; (void)data;
    if (base == WIFI_EVENT && id == WIFI_EVENT_STA_START && door_config_is_provisioned() && !s_selecting_network)
        esp_wifi_connect();
    else if (base == WIFI_EVENT && id == WIFI_EVENT_STA_DISCONNECTED && door_config_is_provisioned() && !s_selecting_network) {
        s_connected = false;
        s_websocket_connected = false;
        status_led_set(true);
        esp_wifi_connect();
    } else if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
        s_connected = true;
        ESP_LOGI(TAG, "Station connected; setup page remains disabled after provisioning");
    }
}

esp_err_t door_wifi_start(void)
{
    gpio_set_level(STATUS_LED_GPIO, STATUS_LED_ON_LEVEL);
    gpio_config_t led_config = {
        .pin_bit_mask = 1ULL << STATUS_LED_GPIO,
        .mode = GPIO_MODE_OUTPUT,
        .pull_up_en = GPIO_PULLUP_DISABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type = GPIO_INTR_DISABLE,
    };
    ESP_ERROR_CHECK(gpio_config(&led_config));
    status_led_set(true);

    tcpip_adapter_init();
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    wifi_init_config_t init = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&init));
    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, wifi_event, NULL));
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, wifi_event, NULL));

    uint8_t mac[6];
    esp_read_mac(mac, ESP_MAC_WIFI_SOFTAP);
    char ap_suffix[9];
    snprintf(ap_suffix, sizeof(ap_suffix), "%02X%02X%02X%02X", mac[2], mac[3], mac[4], mac[5]);
    char ap_ssid[33];
    snprintf(ap_ssid, sizeof(ap_ssid), "SmartDoor-%s", ap_suffix);
    door_config_t saved;
    door_config_get(&saved);

    wifi_config_t ap = {0};
    strlcpy((char *)ap.ap.ssid, ap_ssid, sizeof(ap.ap.ssid));
    strlcpy((char *)ap.ap.password, ap_suffix, sizeof(ap.ap.password));
    ap.ap.ssid_len = strlen(ap_ssid);
    ap.ap.channel = 1;
    ap.ap.max_connection = 4;
    ap.ap.authmode = WIFI_AUTH_WPA_WPA2_PSK;

    wifi_config_t sta = {0};
    if (door_config_is_provisioned()) {
        wifi_scan_config_t scan = { .show_hidden = false };
        s_selecting_network = true;
        ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
        ESP_ERROR_CHECK(esp_wifi_start());
        ESP_ERROR_CHECK(esp_wifi_scan_start(&scan, true));
        uint16_t count = 0;
        ESP_ERROR_CHECK(esp_wifi_scan_get_ap_num(&count));
        wifi_ap_record_t *records = count ? calloc(count, sizeof(*records)) : NULL;
        int best_rssi = -127;
        int best = -1;
        if (records) ESP_ERROR_CHECK(esp_wifi_scan_get_ap_records(&count, records));
        for (uint16_t r = 0; r < count; ++r) {
            for (int i = 0; i < DOOR_WIFI_NETWORKS_MAX; ++i) {
                if (saved.ssid[i][0] && !strcmp((char *)records[r].ssid, saved.ssid[i]) && records[r].rssi > best_rssi) {
                    best_rssi = records[r].rssi;
                    best = i;
                }
            }
        }
        free(records);
        if (best < 0) best = 0;
        strlcpy((char *)sta.sta.ssid, saved.ssid[best], sizeof(sta.sta.ssid));
        strlcpy((char *)sta.sta.password, saved.wifi_password[best], sizeof(sta.sta.password));
        sta.sta.threshold.authmode = saved.wifi_password[best][0] ? WIFI_AUTH_WPA2_PSK : WIFI_AUTH_OPEN;
        s_selecting_network = false;
    }
    if (door_config_is_provisioned()) {
        ESP_ERROR_CHECK(esp_wifi_set_config(ESP_IF_WIFI_STA, &sta));
        ESP_ERROR_CHECK(esp_wifi_connect());
    } else {
        ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_AP));
        ESP_ERROR_CHECK(esp_wifi_set_config(ESP_IF_WIFI_AP, &ap));
    }
    if (!door_config_is_provisioned()) ESP_ERROR_CHECK(esp_wifi_start());
    if (!door_config_is_provisioned()) {
        ESP_LOGW(TAG, "Config AP: %s, page: http://192.168.4.1", ap_ssid);
    }
    if (xTaskCreate(status_led_task, "status_led", 1024, NULL, 2, NULL) != pdPASS)
        return ESP_ERR_NO_MEM;
    return ESP_OK;
}

bool door_wifi_station_connected(void) { return s_connected; }

void door_wifi_set_websocket_connected(bool connected)
{
    s_websocket_connected = connected;
    if (connected) status_led_set(false);
}
