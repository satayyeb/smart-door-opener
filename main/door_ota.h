#pragma once

#include <stdbool.h>
#include <stddef.h>
#include "esp_err.h"

#ifndef FIRMWARE_VERSION
#define FIRMWARE_VERSION "0.0.0-dev"
#endif

typedef enum {
    DOOR_OTA_IDLE,
    DOOR_OTA_CHECKING,
    DOOR_OTA_AVAILABLE,
    DOOR_OTA_DOWNLOADING,
    DOOR_OTA_VERIFYING,
    DOOR_OTA_READY,
    DOOR_OTA_UP_TO_DATE,
    DOOR_OTA_ERROR,
} door_ota_state_t;

typedef struct {
    door_ota_state_t state;
    unsigned progress;
    char current_version[32];
    char available_version[32];
    char message[128];
} door_ota_status_t;

esp_err_t door_ota_check(void);
esp_err_t door_ota_start(void);
esp_err_t door_ota_update_latest(void);
void door_ota_get_status(door_ota_status_t *status);
const char *door_ota_state_name(door_ota_state_t state);
