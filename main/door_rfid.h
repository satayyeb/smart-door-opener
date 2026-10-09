#pragma once

#include <stdbool.h>
#include <stdint.h>
#include "esp_err.h"

#define DOOR_RFID_MAX_CARDS 16
#define DOOR_RFID_NAME_MAX 48

typedef struct {
    unsigned id;
    bool pending;
    char name[DOOR_RFID_NAME_MAX + 1];
} door_rfid_card_t;

typedef struct {
    bool ready;
    bool enrolling;
    char message[128];
    unsigned count;
    door_rfid_card_t cards[DOOR_RFID_MAX_CARDS];
} door_rfid_status_t;

esp_err_t door_rfid_init(void);
void door_rfid_get_status(door_rfid_status_t *out);
esp_err_t door_rfid_enroll(const char *name);
esp_err_t door_rfid_cancel(void);
esp_err_t door_rfid_delete(unsigned id);
esp_err_t door_rfid_erase(void);
