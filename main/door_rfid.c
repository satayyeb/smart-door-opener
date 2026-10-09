#include "door_rfid.h"

#include <stdio.h>
#include <string.h>
#include "door_config.h"
#include "door_control.h"
#include "driver/gpio.h"
#include "esp_log.h"
#include "esp_system.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "nvs.h"

/* ponytail: software SPI suits one RC522; move relay or reader bus for higher throughput.
 * Software SPI preserves GPIO 12 (HSPI MISO) for the existing relay. */
#define RFID_SCK GPIO_NUM_14
#define RFID_MOSI GPIO_NUM_13
#define RFID_MISO GPIO_NUM_4
#define RFID_CS GPIO_NUM_5
#define RFID_BLOCK 28
#define RFID_TRAILER 31
#define ENROLL_TICKS pdMS_TO_TICKS(60000)

/* MFRC522 registers. */
#define COMMAND 0x01
#define COM_IRQ 0x04
#define ERROR_REG 0x06
#define STATUS2 0x08
#define FIFO_DATA 0x09
#define FIFO_LEVEL 0x0a
#define CONTROL 0x0c
#define BIT_FRAMING 0x0d
#define MODE 0x11
#define TX_CONTROL 0x14
#define TX_ASK 0x15
#define TMODE 0x2a
#define TPRESCALER 0x2b
#define TRELOAD_H 0x2c
#define TRELOAD_L 0x2d
#define VERSION 0x37

#define STORE_VERSION 1
#define EMPTY 0
#define PENDING 1
#define ACTIVE 2
#define REVOKED 3

typedef struct {
    uint8_t state;
    uint8_t uid_length;
    uint8_t uid[7];
    uint8_t key[6];
    uint8_t secret[16];
    char name[DOOR_RFID_NAME_MAX + 1];
} card_t;

typedef struct {
    uint32_t version;
    card_t cards[DOOR_RFID_MAX_CARDS];
} store_t;

static const char *TAG = "door_rfid";
static store_t s_store;
static SemaphoreHandle_t s_mutex;
static bool s_ready;
static bool s_enrolling;
static TickType_t s_enroll_start;
static char s_name[DOOR_RFID_NAME_MAX + 1];
static char s_message[128] = "Reader not initialized";
static bool s_bus_ok;
static const uint8_t DEFAULT_KEY[6] = {255, 255, 255, 255, 255, 255};

static void pin(gpio_num_t gpio, unsigned level)
{
    if (gpio_set_level(gpio, level) != ESP_OK) s_bus_ok = false;
}

static uint8_t spi_byte(uint8_t value)
{
    uint8_t result = 0;
    for (unsigned i = 0; i < 8; ++i) {
        pin(RFID_MOSI, (value >> 7) & 1);
        pin(RFID_SCK, 1);
        result = (result << 1) | gpio_get_level(RFID_MISO);
        pin(RFID_SCK, 0);
        value <<= 1;
    }
    return result;
}

static void reg_write(uint8_t address, uint8_t value)
{
    pin(RFID_CS, 0);
    spi_byte((address << 1) & 0x7e);
    spi_byte(value);
    pin(RFID_CS, 1);
}

static uint8_t reg_read(uint8_t address)
{
    pin(RFID_CS, 0);
    spi_byte(0x80 | ((address << 1) & 0x7e));
    uint8_t result = spi_byte(0);
    pin(RFID_CS, 1);
    return result;
}

static void crc_a(const uint8_t *data, size_t length, uint8_t result[2])
{
    uint16_t crc = 0x6363;
    for (size_t i = 0; i < length; ++i) {
        uint8_t value = data[i] ^ (uint8_t)crc;
        value ^= value << 4;
        crc = (crc >> 8) ^ ((uint16_t)value << 8) ^ ((uint16_t)value << 3) ^ (value >> 4);
    }
    result[0] = crc;
    result[1] = crc >> 8;
}

static bool crc_valid(const uint8_t *data, size_t length)
{
    if (length < 2) return false;
    uint8_t crc[2];
    crc_a(data, length - 2, crc);
    return crc[0] == data[length - 2] && crc[1] == data[length - 1];
}

/* Bounded exchanges run only in the RFID task, never an HTTP callback. */
static bool exchange(uint8_t command, const uint8_t *tx, size_t tx_length,
                     unsigned tx_bits, uint8_t *rx, size_t *rx_length, unsigned *rx_bits)
{
    if (!s_bus_ok || tx_length > 64 || tx_bits > 7) return false;
    reg_write(COMMAND, 0);
    reg_write(COM_IRQ, 0x7f);
    reg_write(FIFO_LEVEL, 0x80);
    for (size_t i = 0; i < tx_length; ++i) reg_write(FIFO_DATA, tx[i]);
    reg_write(BIT_FRAMING, tx_bits);
    reg_write(COMMAND, command);
    if (command == 0x0c) reg_write(BIT_FRAMING, tx_bits | 0x80);
    TickType_t start = xTaskGetTickCount();
    bool done = false;
    do {
        uint8_t irq = reg_read(COM_IRQ);
        if (irq & (command == 0x0e ? 0x10 : 0x30)) { done = true; break; }
        if (irq & 0x01) break;
        vTaskDelay(1);
    } while ((TickType_t)(xTaskGetTickCount() - start) < pdMS_TO_TICKS(50));
    reg_write(BIT_FRAMING, tx_bits);
    if (!done || !s_bus_ok || (reg_read(ERROR_REG) & 0xdf)) return false;
    if (command == 0x0e) return (reg_read(STATUS2) & 0x08) != 0 && s_bus_ok;
    size_t count = reg_read(FIFO_LEVEL);
    unsigned last_bits = reg_read(CONTROL) & 7;
    if (!rx || !rx_length || count > *rx_length || count == 0) return false;
    for (size_t i = 0; i < count; ++i) rx[i] = reg_read(FIFO_DATA);
    *rx_length = count;
    if (rx_bits) *rx_bits = last_bits;
    return s_bus_ok;
}

static bool select_card(uint8_t uid[7], uint8_t *uid_length)
{
    reg_write(STATUS2, reg_read(STATUS2) & ~0x08);
    uint8_t tx[9] = {0x26}, rx[5];
    size_t length = sizeof(rx);
    unsigned bits = 0;
    if (!exchange(0x0c, tx, 1, 7, rx, &length, &bits) || length != 2 || bits) return false;
    *uid_length = 0;
    for (unsigned cascade = 0; cascade < 2; ++cascade) {
        tx[0] = cascade ? 0x95 : 0x93;
        tx[1] = 0x20;
        length = sizeof(rx);
        if (!exchange(0x0c, tx, 2, 0, rx, &length, &bits) || length != 5 || bits ||
            (uint8_t)(rx[0] ^ rx[1] ^ rx[2] ^ rx[3]) != rx[4]) return false;
        memcpy(tx + 2, rx, 5);
        tx[1] = 0x70;
        crc_a(tx, 7, tx + 7);
        bool more = rx[0] == 0x88;
        if (cascade && more) return false;
        memcpy(uid + *uid_length, rx + (more ? 1 : 0), more ? 3 : 4);
        *uid_length += more ? 3 : 4;
        length = sizeof(rx);
        if (!exchange(0x0c, tx, 9, 0, rx, &length, &bits) || length != 3 || bits || !crc_valid(rx, length)) return false;
        if (more) { if (!(rx[0] & 4)) return false; }
        else return rx[0] == 0x08; /* MIFARE Classic 1K only. */
    }
    return false;
}

static bool authenticate(const uint8_t uid[7], uint8_t uid_length, const uint8_t key[6])
{
    if (uid_length != 4 && uid_length != 7) return false;
    uint8_t frame[12] = {0x60, RFID_BLOCK};
    memcpy(frame + 2, key, 6);
    memcpy(frame + 8, uid + uid_length - 4, 4);
    return exchange(0x0e, frame, sizeof(frame), 0, NULL, NULL, NULL);
}

static bool read_block(uint8_t block, uint8_t data[16])
{
    uint8_t frame[4] = {0x30, block}, response[18];
    crc_a(frame, 2, frame + 2);
    size_t length = sizeof(response);
    unsigned bits = 0;
    if (!exchange(0x0c, frame, sizeof(frame), 0, response, &length, &bits) ||
        length != 18 || bits || !crc_valid(response, length)) return false;
    memcpy(data, response, 16);
    return true;
}

static bool ack(const uint8_t *frame, size_t length)
{
    uint8_t response[1];
    size_t count = sizeof(response);
    unsigned bits = 0;
    return exchange(0x0c, frame, length, 0, response, &count, &bits) &&
           count == 1 && bits == 4 && (response[0] & 15) == 0x0a;
}

static bool write_block(uint8_t block, const uint8_t data[16])
{
    uint8_t command[4] = {0xa0, block}, frame[18];
    crc_a(command, 2, command + 2);
    if (!ack(command, sizeof(command))) return false;
    memcpy(frame, data, 16);
    crc_a(frame, 16, frame + 16);
    return ack(frame, sizeof(frame));
}

static void finish_card(void)
{
    uint8_t halt[4] = {0x50, 0}, response[1];
    size_t length = sizeof(response);
    crc_a(halt, 2, halt + 2);
    exchange(0x0c, halt, sizeof(halt), 0, response, &length, NULL);
    reg_write(STATUS2, reg_read(STATUS2) & ~0x08);
    reg_write(COMMAND, 0);
}

static void reset_field(void)
{
    reg_write(STATUS2, reg_read(STATUS2) & ~0x08);
    reg_write(TX_CONTROL, reg_read(TX_CONTROL) & ~3);
    vTaskDelay(pdMS_TO_TICKS(10));
    reg_write(TX_CONTROL, reg_read(TX_CONTROL) | 3);
    vTaskDelay(pdMS_TO_TICKS(10));
}

static esp_err_t persist(const store_t *next)
{
    nvs_handle_t handle = 0;
    esp_err_t err = nvs_open("rfid", NVS_READWRITE, &handle);
    if (err == ESP_OK) err = nvs_set_blob(handle, "cards", next, sizeof(*next));
    if (err == ESP_OK) err = nvs_commit(handle);
    if (handle) nvs_close(handle);
    if (err == ESP_OK) s_store = *next;
    return err;
}

static bool same_uid(const card_t *card, const uint8_t *uid, uint8_t length)
{
    return card->state != EMPTY && card->uid_length == length && !memcmp(card->uid, uid, length);
}

static bool credential_matches(const card_t *card, const uint8_t data[16])
{
    unsigned difference = 0;
    for (unsigned i = 0; i < 16; ++i) difference |= card->secret[i] ^ data[i];
    return difference == 0;
}

static bool card_authorized(const uint8_t uid[7], uint8_t uid_length)
{
    if (uid_length != 4 && uid_length != 7) return false;
    for (unsigned i = 0; i < DOOR_RFID_MAX_CARDS; ++i) {
        const card_t *card = &s_store.cards[i];
        if (card->state != ACTIVE || !same_uid(card, uid, uid_length)) continue;
        uint8_t data[16];
        return authenticate(uid, uid_length, card->key) && read_block(RFID_BLOCK, data) &&
               credential_matches(card, data);
    }
    return false;
}

static void enroll_card(const uint8_t uid[7], uint8_t uid_length)
{
    int slot = -1;
    for (unsigned i = 0; i < DOOR_RFID_MAX_CARDS; ++i) {
        if (same_uid(&s_store.cards[i], uid, uid_length)) { slot = i; break; }
    }
    if (slot >= 0 && s_store.cards[slot].state == ACTIVE) {
        strlcpy(s_message, "Card already enrolled; delete it before renaming", sizeof(s_message));
        return;
    }
    if (slot < 0) {
        for (unsigned i = 0; i < DOOR_RFID_MAX_CARDS; ++i)
            if (s_store.cards[i].state == EMPTY) { slot = i; break; }
    }
    if (slot < 0) {
        for (unsigned i = 0; i < DOOR_RFID_MAX_CARDS; ++i)
            if (s_store.cards[i].state == REVOKED) { slot = i; break; }
    }
    if (slot < 0) { strlcpy(s_message, "Card list full", sizeof(s_message)); return; }
    store_t next = s_store;
    card_t *card = &next.cards[slot];
    bool known = same_uid(card, uid, uid_length);
    if (!known) {
        /* Only dedicated cards with a factory-key, transport-mode sector 7. */
        if (!authenticate(uid, uid_length, DEFAULT_KEY)) {
            strlcpy(s_message, "Sector 7 does not accept factory key; use a blank card", sizeof(s_message));
            return;
        }
        uint8_t trailer[16];
        if (!read_block(RFID_TRAILER, trailer) || memcmp(trailer + 6, "\xff\x07\x80", 3)) {
            strlcpy(s_message, "Sector 7 access conditions unsupported; card unchanged", sizeof(s_message));
            return;
        }
        memset(card, 0, sizeof(*card));
        card->uid_length = uid_length;
        memcpy(card->uid, uid, uid_length);
        esp_fill_random(card->key, sizeof(card->key));
        esp_fill_random(card->secret, sizeof(card->secret));
    } else if (!authenticate(uid, uid_length, card->key)) {
        finish_card();
        reset_field();
        uint8_t selected[7], length;
        /* Recovery when power failed before the new trailer was written. */
        if (!select_card(selected, &length) || length != uid_length || memcmp(selected, uid, length) ||
            !authenticate(uid, uid_length, DEFAULT_KEY)) {
            strlcpy(s_message, "Card authentication failed", sizeof(s_message));
            return;
        }
    }
    card->state = PENDING;
    strlcpy(card->name, s_name, sizeof(card->name));
    /* Save keys BEFORE modifying card; interrupted enrollment remains denied. */
    if (persist(&next) != ESP_OK) {
        strlcpy(s_message, "Storage failed; card unchanged", sizeof(s_message));
        return;
    }
    uint8_t trailer[16] = {0};
    memcpy(trailer, card->key, 6);
    trailer[6] = 0xff; trailer[7] = 0x07; trailer[8] = 0x80; trailer[9] = 0x69;
    esp_fill_random(trailer + 10, 6);
    if (!write_block(RFID_BLOCK, card->secret) || !write_block(RFID_TRAILER, trailer)) {
        strlcpy(s_message, "Card write failed; pending card denied. Retry enrollment", sizeof(s_message));
        s_enrolling = false;
        return;
    }
    finish_card();
    /* Reset RF field to restart authentication with the new sector key. */
    reset_field();
    uint8_t selected[7], length, data[16];
    if (!select_card(selected, &length) || !same_uid(card, selected, length) ||
        !authenticate(selected, length, card->key) || !read_block(RFID_BLOCK, data) ||
        !credential_matches(card, data)) {
        strlcpy(s_message, "Verification failed; pending card denied. Retry enrollment", sizeof(s_message));
    } else {
        card->state = ACTIVE;
        if (persist(&next) == ESP_OK) strlcpy(s_message, "Card enrolled; remove it before testing", sizeof(s_message));
        else strlcpy(s_message, "Storage failed; pending card denied. Retry enrollment", sizeof(s_message));
    }
    s_enrolling = false;
}

static void reader_task(void *unused)
{
    (void)unused;
    for (;;) {
        xSemaphoreTake(s_mutex, portMAX_DELAY);
        if (s_enrolling && (!door_config_panel_password_set() || !door_config_is_provisioned() ||
            (TickType_t)(xTaskGetTickCount() - s_enroll_start) >= ENROLL_TICKS)) {
            s_enrolling = false;
            strlcpy(s_message, "Enrollment expired or panel password removed", sizeof(s_message));
        }
        uint8_t uid[7], uid_length;
        if (s_ready && select_card(uid, &uid_length)) {
            if (s_enrolling) enroll_card(uid, uid_length);
            else {
                bool allowed = card_authorized(uid, uid_length);
                if (allowed) {
                    esp_err_t err = door_control_open();
                    strlcpy(s_message, err == ESP_OK ? "Card accepted; door opened" : "Relay busy or unavailable", sizeof(s_message));
                    if (err == ESP_OK) ESP_LOGI(TAG, "Authenticated card opened door");
                } else strlcpy(s_message, "Card denied", sizeof(s_message));
            }
            finish_card();
        }
        if (!s_bus_ok) {
            s_ready = false;
            strlcpy(s_message, "Reader GPIO error; restart required", sizeof(s_message));
        }
        xSemaphoreGive(s_mutex);
        vTaskDelay(pdMS_TO_TICKS(150));
    }
}

esp_err_t door_rfid_init(void)
{
    s_mutex = xSemaphoreCreateMutex();
    if (!s_mutex) return ESP_ERR_NO_MEM;
    store_t loaded = {.version = STORE_VERSION};
    nvs_handle_t handle = 0;
    esp_err_t err = nvs_open("rfid", NVS_READONLY, &handle);
    if (err == ESP_OK) {
        size_t length = sizeof(loaded);
        err = nvs_get_blob(handle, "cards", &loaded, &length);
        nvs_close(handle);
        if (err == ESP_ERR_NVS_NOT_FOUND) { memset(&loaded, 0, sizeof(loaded)); loaded.version = STORE_VERSION; }
        else if (err != ESP_OK) return err;
        else if (length != sizeof(loaded) || loaded.version != STORE_VERSION) return ESP_ERR_INVALID_STATE;
    } else if (err != ESP_ERR_NVS_NOT_FOUND) return err;
    for (unsigned i = 0; i < DOOR_RFID_MAX_CARDS; ++i) {
        card_t *card = &loaded.cards[i];
        if (card->state > REVOKED || (card->state != EMPTY && card->uid_length != 4 && card->uid_length != 7) ||
            !memchr(card->name, 0, sizeof(card->name))) return ESP_ERR_INVALID_STATE;
    }
    s_store = loaded;
    s_bus_ok = true;
    pin(RFID_CS, 1);
    pin(RFID_SCK, 0);
    pin(RFID_MOSI, 0);
    gpio_config_t output = {
        .pin_bit_mask = (1ULL << RFID_CS) | (1ULL << RFID_SCK) | (1ULL << RFID_MOSI),
        .mode = GPIO_MODE_OUTPUT, .intr_type = GPIO_INTR_DISABLE,
    };
    gpio_config_t input = {.pin_bit_mask = 1ULL << RFID_MISO, .mode = GPIO_MODE_INPUT, .intr_type = GPIO_INTR_DISABLE};
    if ((err = gpio_config(&output)) != ESP_OK || (err = gpio_config(&input)) != ESP_OK) return err;
    pin(RFID_CS, 1);
    reg_write(COMMAND, 0x0f);
    vTaskDelay(pdMS_TO_TICKS(50));
    uint8_t version = reg_read(VERSION);
    if (!s_bus_ok || (version != 0x91 && version != 0x92)) {
        strlcpy(s_message, "RC522 not detected; check wiring and restart", sizeof(s_message));
        return ESP_ERR_NOT_FOUND;
    }
    reg_write(TMODE, 0x80);
    reg_write(TPRESCALER, 0xa9);
    reg_write(TRELOAD_H, 0x03);
    reg_write(TRELOAD_L, 0xe8); /* 25 ms hardware timeout. */
    reg_write(TX_ASK, 0x40);
    reg_write(MODE, 0x3d);
    reg_write(TX_CONTROL, reg_read(TX_CONTROL) | 3);
    if (!s_bus_ok) return ESP_FAIL;
    s_ready = true;
    strlcpy(s_message, "Ready; only enrolled cards can open door", sizeof(s_message));
    if (xTaskCreate(reader_task, "rfid", 4096, NULL, 3, NULL) != pdPASS) {
        s_ready = false;
        return ESP_ERR_NO_MEM;
    }
    ESP_LOGI(TAG, "RC522 ready (version %02x); Classic 1K sector 7", version);
    return ESP_OK;
}

void door_rfid_get_status(door_rfid_status_t *out)
{
    memset(out, 0, sizeof(*out));
    if (!s_mutex) { strlcpy(out->message, s_message, sizeof(out->message)); return; }
    xSemaphoreTake(s_mutex, portMAX_DELAY);
    out->ready = s_ready;
    out->enrolling = s_enrolling;
    strlcpy(out->message, s_message, sizeof(out->message));
    for (unsigned i = 0; i < DOOR_RFID_MAX_CARDS; ++i) {
        const card_t *card = &s_store.cards[i];
        if (card->state != ACTIVE && card->state != PENDING) continue;
        door_rfid_card_t *entry = &out->cards[out->count++];
        entry->id = i + 1;
        entry->pending = card->state == PENDING;
        strlcpy(entry->name, card->name, sizeof(entry->name));
    }
    xSemaphoreGive(s_mutex);
}

esp_err_t door_rfid_enroll(const char *name)
{
    if (!name || !name[0] || strlen(name) > DOOR_RFID_NAME_MAX) return ESP_ERR_INVALID_ARG;
    bool visible = false;
    for (const unsigned char *p = (const unsigned char *)name; *p; ++p) {
        if (*p < 32 || *p == 127) return ESP_ERR_INVALID_ARG;
        if (*p != ' ') visible = true;
    }
    if (!visible || !s_mutex) return ESP_ERR_INVALID_ARG;
    xSemaphoreTake(s_mutex, portMAX_DELAY);
    esp_err_t err = ESP_OK;
    if (!s_ready || s_enrolling || !door_config_is_provisioned() || !door_config_panel_password_set()) err = ESP_ERR_INVALID_STATE;
    else {
        for (unsigned i = 0; i < DOOR_RFID_MAX_CARDS; ++i)
            if (s_store.cards[i].state == ACTIVE && !strcmp(s_store.cards[i].name, name)) err = ESP_ERR_INVALID_ARG;
        if (err == ESP_OK) {
            strlcpy(s_name, name, sizeof(s_name));
            s_enroll_start = xTaskGetTickCount();
            s_enrolling = true;
            strlcpy(s_message, "Tap dedicated Classic 1K card within 60 seconds; sector 7 will be overwritten", sizeof(s_message));
        }
    }
    xSemaphoreGive(s_mutex);
    return err;
}

esp_err_t door_rfid_cancel(void)
{
    if (!s_mutex) return ESP_ERR_INVALID_STATE;
    xSemaphoreTake(s_mutex, portMAX_DELAY);
    s_enrolling = false;
    strlcpy(s_message, "Enrollment cancelled", sizeof(s_message));
    xSemaphoreGive(s_mutex);
    return ESP_OK;
}

esp_err_t door_rfid_delete(unsigned id)
{
    if (!s_mutex || !id || id > DOOR_RFID_MAX_CARDS) return ESP_ERR_INVALID_ARG;
    xSemaphoreTake(s_mutex, portMAX_DELAY);
    store_t next = s_store;
    card_t *card = &next.cards[id - 1];
    esp_err_t err = ESP_ERR_NOT_FOUND;
    if (card->state == ACTIVE || card->state == PENDING) {
        /* Retain revoked keys for re-enrollment until this slot is reused. */
        card->state = REVOKED;
        memset(card->name, 0, sizeof(card->name));
        err = persist(&next);
        if (err == ESP_OK) {
            s_enrolling = false;
            strlcpy(s_message, "Card deleted; access revoked", sizeof(s_message));
        }
    }
    xSemaphoreGive(s_mutex);
    return err;
}

esp_err_t door_rfid_erase(void)
{
    if (!s_mutex) return ESP_ERR_INVALID_STATE;
    xSemaphoreTake(s_mutex, portMAX_DELAY);
    nvs_handle_t handle = 0;
    esp_err_t err = nvs_open("rfid", NVS_READWRITE, &handle);
    if (err == ESP_OK) err = nvs_erase_all(handle);
    if (err == ESP_OK) err = nvs_commit(handle);
    if (handle) nvs_close(handle);
    if (err == ESP_OK) {
        memset(&s_store, 0, sizeof(s_store));
        s_store.version = STORE_VERSION;
        s_enrolling = false;
        s_ready = false;
        strlcpy(s_message, "Cards erased; restarting", sizeof(s_message));
    }
    xSemaphoreGive(s_mutex);
    return err;
}
