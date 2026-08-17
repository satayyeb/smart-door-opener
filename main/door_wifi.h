#pragma once
#include <stdbool.h>
#include "esp_err.h"

esp_err_t door_wifi_start(void);
bool door_wifi_station_connected(void);
void door_wifi_set_websocket_connected(bool connected);
