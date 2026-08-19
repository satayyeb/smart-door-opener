#pragma once
#include "esp_err.h"

esp_err_t door_socket_start(void);
void door_socket_request_ota_pause(void);
esp_err_t door_socket_pause_for_ota(void);
void door_socket_resume_after_ota(void);
