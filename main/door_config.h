#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "esp_err.h"

#define DOOR_CONFIG_VERSION 2
#define DOOR_SSID_MAX 32
#define DOOR_WIFI_PASSWORD_MAX 64
#define DOOR_WS_URI_MAX 255
#define DOOR_TOKEN_MAX 191
#define DOOR_ADMIN_PASSWORD_MIN 8
#define DOOR_DEFAULT_USERNAME "admin"
#define DOOR_DEFAULT_PASSWORD "admin"
#define DOOR_SETUP_AP_PASSWORD "adminadmin"

typedef struct {
    uint32_t version;
    bool must_change_password;
    char ssid[DOOR_SSID_MAX + 1];
    char wifi_password[DOOR_WIFI_PASSWORD_MAX + 1];
    char websocket_uri[DOOR_WS_URI_MAX + 1];
    char authorization_token[DOOR_TOKEN_MAX + 1];
    uint8_t password_salt[16];
    uint8_t password_hash[32];
} door_config_t;

esp_err_t door_config_init(void);
bool door_config_is_provisioned(void);
bool door_config_must_change_password(void);
void door_config_get(door_config_t *out);
esp_err_t door_config_save(const char *ssid, const char *wifi_password,
                           const char *websocket_uri, const char *authorization_token);
esp_err_t door_config_change_password(const char *new_password);
bool door_config_check_password(const char *password);
esp_err_t door_config_erase(void);
